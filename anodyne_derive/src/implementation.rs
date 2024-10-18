use core::range::{Range, RangeFrom, RangeInclusive};
use std::ops::{RangeTo, RangeToInclusive};

use darling::{FromField, FromMeta};
use proc_macro2::TokenStream;
use quote::{quote, ToTokens};
use syn::{
    spanned::Spanned, Data, DeriveInput, Error, Expr, Fields, Ident, LitInt, LitStr, Result,
};

pub(crate) fn derive_validates_impl(input: DeriveInput) -> Result<TokenStream> {
    let mut impls = Vec::new();

    let struct_ident = &input.ident;
    let struct_ident_capitalized = &input.ident.to_string().to_uppercase();
    let static_ident = quote::format_ident!("__{}_FIELD_DEFS", struct_ident_capitalized);

    // TODO: rename this, it encapsulates more now
    let static_validation_data = match &input.data {
        Data::Struct(syn::DataStruct { fields, .. }) => {
            let mut impls = quote! {};

            let field_ids = fields
                .iter()
                .map(|item| item.ident.as_ref().unwrap())
                .collect::<Vec<_>>();
            let field_count = field_ids.len();

            let form_field_configs = derive_form_field_configs(fields)?;

            let labels = form_field_configs
                .iter()
                .map(|cfg| cfg.label.as_ref().unwrap())
                .collect::<Vec<_>>();
            let input_types = form_field_configs
                .iter()
                .map(|cfg| cfg.input_type.as_ref().unwrap().0.clone())
                .collect::<Vec<_>>();

            let static_defs = quote!(
                static #static_ident: [::anodyne::types::FormFieldConfig; #field_count] = [
                    #(
                        ::anodyne::types::FormFieldConfig::new(
                            stringify!(#field_ids),
                            #labels,
                            #input_types,
                            false,
                        ),
                    )*
                ];
            );

            impls.extend(static_defs);

            let mut validation_branches = quote! {};

            validation_branches.extend(generate_form_trait_len_validations(&form_field_configs));
            validation_branches.extend(generate_form_trait_field_match_validations(
                &form_field_configs,
            ));
            validation_branches.extend(generate_form_trait_regex_validations(
                struct_ident,
                &form_field_configs,
            ));
            // TODO: handle `required` attribute by looking for Option<T>

            let form_trait = quote! {
                impl ::anodyne::traits::Form for #struct_ident {
                    fn validate(&self) -> Result<(), ::std::collections::HashMap<&'static str, Vec<&'static str>>> {
                        let mut error_map = ::std::collections::HashMap::<&'static str, Vec<&'static str>>::new();

                        #validation_branches

                        if error_map.len() > 0 {
                            Err(error_map)
                        } else {
                            Ok(())
                        }
                    }

                    fn field_configs(&self) -> &'static [::anodyne::types::FormFieldConfig] {
                        &#static_ident
                    }
                }
            };

            impls.extend(form_trait);

            impls
        }
        _ => return Err(Error::new(input.span(), "This only works for struct")),
    };

    impls.push(static_validation_data);

    Ok(quote!(
        #(#impls)*
    ))
}

#[derive(Debug)]
enum AnyRange {
    Range(Range<usize>),
    #[allow(unused)] // TODO
    RangeFrom(RangeFrom<usize>),
    #[allow(unused)] // TODO
    RangeTo(RangeTo<usize>),
    // Unsupported, redundant, just don't specify
    //RangeFull(RangeFull<usize>),
    RangeInclusive(RangeInclusive<usize>),
    #[allow(unused)] // TODO
    RangeToInclusive(RangeToInclusive<usize>),
}

#[derive(Debug)]
enum StringLenRange {
    Exact(usize),
    Range(AnyRange),
}

#[derive(Debug)]
struct InputType(syn::Path);

#[derive(FromField)]
#[darling(attributes(form))]
struct FormMeta {
    ident: Option<syn::Ident>,
    #[allow(unused)]
    ty: syn::Type,

    pub name: Option<syn::Ident>,
    pub label: Option<String>,
    pub required: Option<bool>,
    pub input_type: Option<InputType>,
    pub len: Option<StringLenRange>,
    pub regex: Option<String>,
    pub regex_description: Option<String>,
    pub matches: Option<syn::Path>,
}

impl std::fmt::Debug for FormMeta {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt.debug_struct("FormMeta")
            .field_with("name", |f| f.write_str(&format!("{:?}", self.name)))
            .field_with("label", |f| f.write_str(&format!("{:?}", self.label)))
            .field_with("required", |f| f.write_str(&format!("{:?}", self.required)))
            .field_with("input_type", |f| {
                f.write_str(&format!("{:?}", self.input_type))
            })
            .field_with("len", |f| f.write_str(&format!("{:?}", self.len)))
            .field_with("regex", |f| f.write_str(&format!("{:?}", self.regex)))
            .field_with("matches", |f| f.write_str(&format!("{:?}", self.matches)))
            .finish()
    }
}

impl FromMeta for InputType {
    fn from_expr(expr: &Expr) -> darling::Result<Self> {
        match expr {
            // If they used a bad path then the compiler will sort it out
            Expr::Path(expr_path) => Ok(InputType(expr_path.path.clone())),
            // This is trickier, but we can make a best guess at the path they want
            Expr::Lit(v) => {
                let maybe_string = syn::parse2::<LitStr>(v.to_token_stream());

                if let Ok(lit_str) = maybe_string {
                    let owned = lit_str.value();
                    match owned.as_str() {
                        "password" => Ok(InputType(
                            syn::parse_quote! { ::anodyne::types::FormFieldInputType::Password },
                        )),
                        "text" => Ok(InputType(
                            syn::parse_quote! { ::anodyne::types::FormFieldInputType::Text },
                        )),
                        "email" => Ok(InputType(
                            syn::parse_quote! { ::anodyne::types::FormFieldInputType::Email },
                        )),
                        _ => todo!(),
                    }
                } else {
                    Err(darling::Error::unexpected_lit_type(&v.lit))
                }
            }
            _ => Err(darling::Error::unexpected_expr_type(expr)),
        }
    }
}

impl FromMeta for StringLenRange {
    fn from_expr(expr: &syn::Expr) -> darling::Result<Self> {
        match expr {
            Expr::Range(syn::PatRange {
                start, limits, end, ..
            }) => {
                let maybe_start = start
                    .as_ref()
                    .map(|v| syn::parse2::<LitInt>(v.to_token_stream()).ok())
                    .unwrap_or_default()
                    .and_then(|v| v.base10_parse::<usize>().ok());
                let maybe_end = end
                    .as_ref()
                    .map(|v| syn::parse2::<LitInt>(v.to_token_stream()).ok())
                    .unwrap_or_default()
                    .and_then(|v| v.base10_parse::<usize>().ok());

                let string_len_range = match (maybe_start, limits, maybe_end) {
                    (Some(start), range_type, Some(end)) => match range_type {
                        syn::RangeLimits::HalfOpen(_) => {
                            StringLenRange::Range(AnyRange::Range(Range { start, end }))
                        }
                        syn::RangeLimits::Closed(_) => {
                            StringLenRange::Range(AnyRange::RangeInclusive(RangeInclusive {
                                start,
                                end,
                            }))
                        }
                    },
                    _ => todo!(),
                };

                Ok(string_len_range)
            }
            Expr::Lit(lit_val) => {
                let exact_size = syn::parse2::<LitInt>(lit_val.to_token_stream())
                    .ok()
                    .and_then(|v| v.base10_parse::<usize>().ok());

                if let Some(v) = exact_size {
                    Ok(StringLenRange::Exact(v))
                } else {
                    // TODO: I don't think this is the right function to call, we'll see how it
                    // behaves
                    Err(darling::Error::unexpected_lit_type(&lit_val.lit))
                }
            }
            _ => Err(darling::Error::unexpected_expr_type(expr)),
        }
    }
}

fn derive_form_field_configs(fields: &Fields) -> Result<Vec<FormMeta>> {
    let mut configs = vec![];

    for field in fields {
        let mut meta = FormMeta::from_field(field)?;

        meta.name.get_or_insert(meta.ident.clone().unwrap());
        meta.label.get_or_insert(snake_to_capitalized(
            meta.name.as_ref().unwrap().to_string().as_str(),
        ));
        meta.input_type.get_or_insert(InputType(
            syn::parse_quote! { ::anodyne::types::FormFieldInputType::Text },
        ));

        configs.push(meta);
    }

    // ensure that any `matches` values match something in the field list
    let mut all_field_idents = fields.iter().flat_map(|f| &f.ident);
    let matches_specified = configs
        .iter()
        .filter_map(|cfg| cfg.matches.as_ref().map(|v| v.get_ident()))
        .flatten()
        .collect::<Vec<_>>();
    for match_required in matches_specified.iter() {
        if !all_field_idents.any(|id| id.to_string().eq(&match_required.to_string())) {
            return Err(Error::new(
                match_required.span(),
                "`matches` attribute doesn't reference any field in this struct",
            ));
        }
    }
    // TODO: technically they probably did something wrong if `match = same_name_as_field`
    //       should probably make that an error

    // TODO: it should be an error for two fields to have the same `name` attribute

    Ok(configs)
}

fn snake_to_capitalized(name: &str) -> String {
    name.replace("_", " ")
        .split(" ")
        .map(|word| {
            let mut c = word.chars();
            match c.next() {
                None => String::new(),
                Some(f) => f.to_uppercase().chain(c).collect(),
            }
        })
        .collect::<Vec<String>>()
        .join(" ")
}

fn insert_error(ident: &Ident) -> TokenStream {
    quote! {
        error_map.entry(stringify!(#ident)).or_insert(vec![])
    }
}

fn generate_form_trait_len_validations(configs: &[FormMeta]) -> TokenStream {
    let mut validations = quote! {};

    for config in configs.iter() {
        let ident = config.ident.as_ref().unwrap();
        let label = config.label.as_ref().unwrap();
        let err = insert_error(config.name.as_ref().unwrap());
        if let Some(len_range) = &config.len {
            match len_range {
                StringLenRange::Exact(single_value) => {
                    validations.extend(quote! {
                        if self.#ident.len() != #single_value {
                            #err.push(concat!(#label, " must be exactly ", #single_value, " characters"))
                        }
                    });
                }
                StringLenRange::Range(any_range) => match any_range {
                    // <Integer>..<Integer>: exclusive range
                    AnyRange::Range(range) => {
                        let min = range.start;
                        let max = range.end;
                        validations.extend(quote! {
                            if !(#min..#max).contains(&self.#ident.len()) {
                                #err.push(
                                    concat!(#label, " must have ", #min, " or more characters but less than ", #max)
                                );
                            }
                        });
                    }
                    AnyRange::RangeFrom(_range_from) => todo!(),
                    AnyRange::RangeTo(_range_to) => todo!(),
                    // <Integer>..=<Integer>: inclusive range
                    AnyRange::RangeInclusive(range_inclusive) => {
                        let min = range_inclusive.start;
                        let max = range_inclusive.end;
                        validations.extend(quote! {
                            if !(#min..#max).contains(&self.#ident.len()) {
                                #err.push(
                                    concat!(#label, " must have between ", #min, " and ", #max, " characters")
                                );
                            }
                        });
                    }
                    AnyRange::RangeToInclusive(_range_to_inclusive) => todo!(),
                },
            }
        }
    }

    validations
}

fn generate_form_trait_field_match_validations(configs: &[FormMeta]) -> TokenStream {
    let mut validations = quote! {};

    for config in configs.iter() {
        let match_rule_source = config.ident.as_ref().unwrap();
        let match_rule_source_label = config.label.as_ref().unwrap();
        let err = insert_error(config.name.as_ref().unwrap());
        if let Some(match_rule_target) = config.matches.as_ref() {
            let match_target_label = configs
                .iter()
                .find(|i| *match_rule_target.get_ident().unwrap() == *i.ident.as_ref().unwrap())
                .unwrap()
                .label
                .as_ref()
                .unwrap();
            validations.extend(quote! {
                if self.#match_rule_source != self.#match_rule_target {
                    #err.push(
                        concat!(#match_rule_source_label, " must match ", #match_target_label)
                    );
                }
            });
        }
    }

    validations
}

fn generate_form_trait_regex_validations(
    struct_ident: &Ident,
    configs: &[FormMeta],
) -> TokenStream {
    let mut validations = quote! {};

    for config in configs.iter() {
        let ident = config.ident.as_ref().unwrap();
        let label = config.label.as_ref().unwrap();
        let err = insert_error(config.name.as_ref().unwrap());

        // TODO: regexes need to be compiled, but Regex::new() isn't a `const fn`. Because of that
        // we can't store the regex in a `static`. `lazy_static!()` might work but it creates
        // a bit of extra work. For now I'm just compiling and running on each invocation.
        //
        // Eventually I will have to use `lazy_static!()`.
        if let Some(re) = &config.regex {
            let struct_name = struct_ident.to_string();
            let field_name = ident.to_string();
            let re_compile = quote! {
                let re = ::anodyne::exports::regex::Regex::new(#re)
                    .expect(
                        concat!(
                            "regex for field `",
                            #struct_name,
                            "::",
                            #field_name,
                            "` failed to compile"
                        )
                    );
            };
            let re_test = if let Some(re_description) = &config.regex_description {
                quote! {
                    if !re.is_match(&self.#ident) {
                        #err.push(
                            concat!(#label, " ", #re_description)
                        );
                    }
                }
            } else {
                quote! {
                    if !re.is_match(self.#ident) {
                        #err.push(
                            concat!(#label, " must match /", #re, "/")
                        );
                    }
                }
            };

            validations.extend(quote! {
                #re_compile
                #re_test
            })
        }
    }

    validations
}

#[allow(unused)]
fn template(configs: &[FormMeta]) -> TokenStream {
    let mut validations = quote! {};

    validations
}
