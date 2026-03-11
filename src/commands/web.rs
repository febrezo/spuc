use anyhow::Result;

pub(crate) fn run(
    port: u16,
    admin_user: &str,
    admin_password: Option<&str>,
    no_login: bool,
) -> Result<()> {
    crate::web::server::run(port, admin_user, admin_password, no_login)
}
