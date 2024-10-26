//! Configuration for an `anodyne` application.

/// Contains all the major groups of configuration information.
pub struct Config {
    #[allow(unused)]
    deployment: DeploymentConfig,
    #[allow(unused)]
    crypto: CryptoConfig,
    #[allow(unused)]
    storage: StorageConfig,
    // TODO: build in some kind of mechanism for feature flags so that you don't need to use some
    //       goofy external service.
}

/// Environments that an application can be deployed in.
pub enum DemploymentEnvironment {
    Development,
    Production,
}

impl DemploymentEnvironment {
    /// Returns `true` if application is deployed in a development environment.
    #[must_use]
    pub fn is_development(&self) -> bool {
        matches!(self, DemploymentEnvironment::Development)
    }

    /// Returns `true` if application is deployed in a production environment.
    #[must_use]
    pub fn is_production(&self) -> bool {
        matches!(self, DemploymentEnvironment::Production)
    }
}

/// Configuration pertaining to the environment an application is deployed in.
pub struct DeploymentConfig {
    #[allow(unused)]
    environment: DemploymentEnvironment,
}

/// Configuration pertaining to cryptographic facilities used by an application.
pub struct CryptoConfig {
    #[allow(unused)]
    app_key: [u8; 16], /* Implement parse, prefix will be `base64:byte_count:{...}`,
                        * `hex:byte_count:{...}` */
}

/// Configuration pertaining to storage facilities used by an application.
pub struct StorageConfig {
    #[allow(unused)]
    database: (),
    #[allow(unused)]
    session: (),
}
