// Simple helper functions for admin API (not using axum directly)

pub fn is_admin_authenticated(auth_header: Option<&str>, admin_token: &Option<String>) -> bool {
    let Some(admin_token) = admin_token else {
        return false;
    };

    if let Some(auth_str) = auth_header {
        if let Some(token) = auth_str.strip_prefix("Bearer ") {
            return token == admin_token;
        }
    }
    
    false
}