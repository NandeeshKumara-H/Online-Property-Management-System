// ===================================================================
// PROPERTY MANAGEMENT SYSTEM - Frontend JavaScript
// ===================================================================

// ===================================================================
// UTILITY FUNCTIONS
// ===================================================================

// Show loading overlay
function showLoading() {
    const overlay = document.getElementById('loadingOverlay');
    if (overlay) {
        overlay.classList.add('active');
        overlay.style.display = 'flex';
    }
}

// Hide loading overlay
function hideLoading() {
    const overlay = document.getElementById('loadingOverlay');
    if (overlay) {
        overlay.classList.remove('active');
        overlay.style.display = 'none';
    }
}

// Show notification
function showNotification(message, type = 'success') {
    // Remove existing notifications
    const existing = document.querySelector('.notification');
    if (existing) {
        existing.remove();
    }

    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.textContent = message;

    // Add to body
    document.body.appendChild(notification);

    // Auto remove after 5 seconds
    setTimeout(() => {
        notification.remove();
    }, 5000);
}

// Format date
function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'long',
        day: 'numeric'
    });
}

// Format currency
function formatCurrency(amount) {
    return new Intl.NumberFormat('en-US', {
        style: 'currency',
        currency: 'USD'
    }).format(amount);
}

// Validate email
function validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(String(email).toLowerCase());
}

// ===================================================================
// API HELPER FUNCTIONS
// ===================================================================

// Make authenticated API request
async function apiRequest(url, options = {}) {
    const token = localStorage.getItem('token');
    
    const defaultHeaders = {
        'Content-Type': 'application/json',
    };

    if (token) {
        defaultHeaders['Authorization'] = `Bearer ${token}`;
    }

    const config = {
        ...options,
        headers: {
            ...defaultHeaders,
            ...options.headers,
        },
    };

    try {
        const response = await fetch(url, config);
        const data = await response.json();

        // Handle unauthorized (token expired)
        if (response.status === 401 || response.status === 403) {
            localStorage.removeItem('token');
            localStorage.removeItem('user');
            window.location.href = '/login.html';
            return null;
        }

        return data;
    } catch (error) {
        console.error('API request failed:', error);
        throw error;
    }
}

// ===================================================================
// AUTHENTICATION HELPERS
// ===================================================================

// Check if user is authenticated
function isAuthenticated() {
    const token = localStorage.getItem('token');
    const user = localStorage.getItem('user');
    return !!(token && user);
}

// Get current user
function getCurrentUser() {
    const userStr = localStorage.getItem('user');
    return userStr ? JSON.parse(userStr) : null;
}

// Logout user
function logout() {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    window.location.href = '/login.html';
}

// Require authentication
function requireAuth() {
    if (!isAuthenticated()) {
        window.location.href = '/login.html';
        return false;
    }
    return true;
}

// Require specific role
function requireRole(role) {
    const user = getCurrentUser();
    if (!user || user.role !== role) {
        window.location.href = '/index.html';
        return false;
    }
    return true;
}

// ===================================================================
// LOCAL STORAGE HELPERS
// ===================================================================

// Save to localStorage
function saveToStorage(key, value) {
    try {
        localStorage.setItem(key, JSON.stringify(value));
        return true;
    } catch (error) {
        console.error('Failed to save to storage:', error);
        return false;
    }
}

// Get from localStorage
function getFromStorage(key, defaultValue = null) {
    try {
        const item = localStorage.getItem(key);
        return item ? JSON.parse(item) : defaultValue;
    } catch (error) {
        console.error('Failed to get from storage:', error);
        return defaultValue;
    }
}

// Remove from localStorage
function removeFromStorage(key) {
    try {
        localStorage.removeItem(key);
        return true;
    } catch (error) {
        console.error('Failed to remove from storage:', error);
        return false;
    }
}

// ===================================================================
// FORM VALIDATION
// ===================================================================

// Validate form field
function validateField(field, rules) {
    const value = field.value.trim();
    const errors = [];

    if (rules.required && !value) {
        errors.push('This field is required');
    }

    if (rules.minLength && value.length < rules.minLength) {
        errors.push(`Minimum length is ${rules.minLength} characters`);
    }

    if (rules.maxLength && value.length > rules.maxLength) {
        errors.push(`Maximum length is ${rules.maxLength} characters`);
    }

    if (rules.email && !validateEmail(value)) {
        errors.push('Invalid email address');
    }

    if (rules.pattern && !new RegExp(rules.pattern).test(value)) {
        errors.push('Invalid format');
    }

    return errors;
}

// Show field error
function showFieldError(field, message) {
    // Remove existing error
    const existingError = field.parentElement.querySelector('.field-error');
    if (existingError) {
        existingError.remove();
    }

    // Add new error
    const errorDiv = document.createElement('div');
    errorDiv.className = 'field-error';
    errorDiv.style.color = 'var(--danger-color)';
    errorDiv.style.fontSize = '0.85rem';
    errorDiv.style.marginTop = '0.25rem';
    errorDiv.textContent = message;
    field.parentElement.appendChild(errorDiv);

    // Add error styling to field
    field.style.borderColor = 'var(--danger-color)';
}

// Clear field error
function clearFieldError(field) {
    const existingError = field.parentElement.querySelector('.field-error');
    if (existingError) {
        existingError.remove();
    }
    field.style.borderColor = '';
}

// ===================================================================
// FILE UPLOAD HELPERS
// ===================================================================

// Validate file
function validateFile(file, options = {}) {
    const {
        maxSize = 5 * 1024 * 1024, // 5MB default
        allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif']
    } = options;

    if (file.size > maxSize) {
        return {
            valid: false,
            error: `File size must be less than ${maxSize / (1024 * 1024)}MB`
        };
    }

    if (!allowedTypes.includes(file.type)) {
        return {
            valid: false,
            error: 'Invalid file type'
        };
    }

    return { valid: true };
}

// Preview image file
function previewImage(file, callback) {
    const reader = new FileReader();
    reader.onload = (e) => {
        callback(e.target.result);
    };
    reader.readAsDataURL(file);
}

// ===================================================================
// DOM MANIPULATION HELPERS
// ===================================================================

// Create element with attributes
function createElement(tag, attributes = {}, children = []) {
    const element = document.createElement(tag);
    
    Object.keys(attributes).forEach(key => {
        if (key === 'className') {
            element.className = attributes[key];
        } else if (key === 'innerHTML') {
            element.innerHTML = attributes[key];
        } else {
            element.setAttribute(key, attributes[key]);
        }
    });

    children.forEach(child => {
        if (typeof child === 'string') {
            element.appendChild(document.createTextNode(child));
        } else {
            element.appendChild(child);
        }
    });

    return element;
}

// ===================================================================
// DEBOUNCE & THROTTLE
// ===================================================================

// Debounce function
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Throttle function
function throttle(func, limit) {
    let inThrottle;
    return function(...args) {
        if (!inThrottle) {
            func.apply(this, args);
            inThrottle = true;
            setTimeout(() => inThrottle = false, limit);
        }
    };
}

// ===================================================================
// SEARCH & FILTER
// ===================================================================

// Filter array by search term
function filterBySearch(items, searchTerm, fields) {
    const term = searchTerm.toLowerCase();
    return items.filter(item => {
        return fields.some(field => {
            const value = item[field];
            return value && value.toString().toLowerCase().includes(term);
        });
    });
}

// Sort array by field
function sortBy(items, field, order = 'asc') {
    return [...items].sort((a, b) => {
        const aVal = a[field];
        const bVal = b[field];
        
        if (aVal < bVal) return order === 'asc' ? -1 : 1;
        if (aVal > bVal) return order === 'asc' ? 1 : -1;
        return 0;
    });
}

// ===================================================================
// ERROR HANDLING
// ===================================================================

// Global error handler
window.addEventListener('error', (event) => {
    console.error('Global error:', event.error);
});

// Unhandled promise rejection handler
window.addEventListener('unhandledrejection', (event) => {
    console.error('Unhandled promise rejection:', event.reason);
});

// ===================================================================
// INITIALIZATION
// ===================================================================

// Initialize app on DOM ready
document.addEventListener('DOMContentLoaded', () => {
    // Hide loading overlay on page load
    hideLoading();

    // Add smooth scrolling
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });

    // Auto-hide notifications on click
    document.addEventListener('click', (e) => {
        if (e.target.classList.contains('notification')) {
            e.target.remove();
        }
    });
});

// ===================================================================
// EXPORT (for use in other scripts)
// ===================================================================

// Make functions globally available
window.propertyApp = {
    showLoading,
    hideLoading,
    showNotification,
    formatDate,
    formatCurrency,
    validateEmail,
    apiRequest,
    isAuthenticated,
    getCurrentUser,
    logout,
    requireAuth,
    requireRole,
    saveToStorage,
    getFromStorage,
    removeFromStorage,
    validateField,
    showFieldError,
    clearFieldError,
    validateFile,
    previewImage,
    createElement,
    debounce,
    throttle,
    filterBySearch,
    sortBy
};
