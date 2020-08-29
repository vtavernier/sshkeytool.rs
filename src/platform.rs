use std::fs::File;
use std::path::Path;

use color_eyre::eyre::Result;

#[cfg(unix)]
pub fn set_file_permissions(fs: &mut File, perms: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = fs.metadata()?.permissions();
    permissions.set_mode(perms);
    Ok(fs.set_permissions(permissions)?)
}

#[cfg(not(unix))]
pub fn set_file_permissions(_fs: &mut File, _perms: u32) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
pub fn set_folder_permissions(dir: &Path, perms: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = dir.metadata()?.permissions();
    permissions.set_mode(perms);
    Ok(std::fs::set_permissions(dir, permissions)?)
}

#[cfg(not(unix))]
pub fn set_folder_permissions(_dir: Path, _perms: u32) -> Result<()> {
    Ok(())
}
