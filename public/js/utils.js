// JS Utilities

// Base URL: Use absolute path if on a different port (like Live Server), else relative
const API_BASE = (window.location.port === '5000') ? '/api' : 'http://localhost:5000/api';

// Authentication Fetch Wrapper
// Automatically attaches Token and handles 401/403
async function authFetch(url, options = {}) {
    const token = localStorage.getItem('token');

    // Set Headers
    const headers = {
        'Content-Type': 'application/json',
        ...options.headers
    };

    if (token) {
        headers['x-auth-token'] = token;
    }

    const config = {
        ...options,
        headers
    };

    try {
        const response = await fetch(API_BASE + url, config);

        if (response.status === 401 || response.status === 403) {
            // Token expired or invalid
            console.warn("Session expired or unauthorized. Redirecting to login.");
            logout();
            return null;
        }

        return response;
    } catch (err) {
        console.error("Network Error:", err);
        return null; // Or throw
    }
}

// Save Auth Info
function saveAuth(token, role, username) {
    localStorage.setItem('token', token);
    localStorage.setItem('role', role);
    localStorage.setItem('username', username);
}

// Logout
function logout() {
    localStorage.clear();
    window.location.href = 'index.html';
}

// Redirect if already logged in (for login page)
function checkLoggedInRedirect() {
    const token = localStorage.getItem('token');
    const role = localStorage.getItem('role');
    if (token && role) {
        if (role === 'admin') window.location.href = 'admin.html';
        else if (role === 'worker') window.location.href = 'worker.html';
        else window.location.href = 'user.html';
    }
}

// Redirect if not logged in (for protected pages)
function checkAuthRedirect(allowedRoles = []) {
    const token = localStorage.getItem('token');
    const role = localStorage.getItem('role');

    if (!token) {
        window.location.href = 'index.html';
        return;
    }

    if (allowedRoles.length > 0 && !allowedRoles.includes(role)) {
        alert("Unauthorized Access");
        logout();
    }
}
