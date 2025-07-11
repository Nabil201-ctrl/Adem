// utils.js
export const API_URL = 'https://adem-backend.onrender.com/api';
export const API_URL_1 = 'http://localhost:3000/api';
export const LOGIN_PATH = '/login-form/index.html';
export const BASE_URL = '';

export function showToast(message, type = 'info') {
    const toast = document.getElementById('toast');
    if (!toast) {
        console.warn('Toast element not found');
        return;
    }
    toast.textContent = message;
    toast.className = `custom-toast show ${type}`;
    setTimeout(() => {
        toast.className = 'custom-toast';
    }, 3000);
}

export function togglePasswordVisibility(inputId, toggleId) {
    const input = document.getElementById(inputId);
    const toggle = document.getElementById(toggleId);
    toggle.addEventListener('click', () => {
        const type = input.getAttribute('type') === 'password' ? 'text' : 'password';
        input.setAttribute('type', type);
        toggle.classList.toggle('fa-eye');
        toggle.classList.toggle('fa-eye-slash');
    });
}

export async function fetchWithRetry(url, options, retries = 3, timeout = 10000) {
    console.log(`Fetching URL: ${url}`); // Debug log
    for (let i = 0; i < retries; i++) {
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), timeout);
            const response = await fetch(url, { ...options, signal: controller.signal });
            clearTimeout(timeoutId);

            if (!response.ok) {
                let errorData = {};
                try {
                    const text = await response.text();
                    errorData = text ? JSON.parse(text) : { message: `HTTP error! status: ${response.status}` };
                    console.log(`Error response from ${url}:`, errorData); // Debug log
                } catch (e) {
                    errorData = { message: `Non-JSON response: ${response.statusText || 'Unknown error'}` };
                    console.error(`Failed to parse error response from ${url}:`, e);
                }
                const error = new Error(errorData.error?.message || errorData.message || `HTTP error! status: ${response.status}`);
                error.error = errorData.error || errorData;
                error.status = response.status; // Ensure status is set
                throw error;
            }
            return await response.json();
        } catch (error) {
            console.error(`Fetch attempt ${i + 1}/${retries} failed for ${url}:`, error);
            if (error.name === 'AbortError') {
                const abortError = new Error('Request timed out');
                abortError.name = 'network';
                throw abortError;
            }
            if (i < retries - 1) {
                await new Promise(resolve => setTimeout(resolve, 1000));
                continue;
            }
            if (error.message.includes('Failed to fetch')) {
                error.name = 'network';
            }
            throw error;
        }
    }
}

export function sanitizeInput(input) {
    // Use DOMPurify from CDN
    return DOMPurify.sanitize(input);
}