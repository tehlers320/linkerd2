#![deny(warnings, rust_2018_idioms)]
#![forbid(unsafe_code)]

mod defaults;
mod index;
pub mod watch;

#[cfg(test)]
mod tests;

use linkerd_policy_controller_core::IpNet;
use std::time;

pub use self::{
    defaults::DefaultPolicy,
    index::{Index, NamespaceIndex, SharedIndex},
};

/// Holds cluster metadata.
#[derive(Clone, Debug)]
pub struct ClusterInfo {
    /// Networks including PodIPs in this cluster.
    ///
    /// Unfortunately, there's no way to discover this at runtime.
    pub networks: Vec<IpNet>,

    /// The namespace where the linkerd control plane is deployed
    pub control_plane_ns: String,

    /// The cluster's mesh identity trust domain.
    pub identity_domain: String,

    /// The cluster-wide default policy.
    pub default_policy: DefaultPolicy,

    /// The cluster-wide default protocol detection timeout.
    pub default_detect_timeout: time::Duration,
}
