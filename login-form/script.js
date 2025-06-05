// Toggle between Student and Admin
const typeButtons = document.querySelectorAll('.type-btn');
typeButtons.forEach(button => {
    button.addEventListener('click', () => {
        typeButtons.forEach(btn => btn.classList.remove('active'));
        button.classList.add('active');
        
        // Add transition effect to form
        const form = document.querySelector('.login-form');
        form.style.opacity = '0';
        setTimeout(() => {
            form.style.opacity = '1';
        }, 200);
    });
});

// Toggle password visibility
const togglePassword = document.querySelector('.toggle-password');
const passwordInput = document.querySelector('#password');

togglePassword.addEventListener('click', () => {
    const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
    passwordInput.setAttribute('type', type);
    togglePassword.classList.toggle('fa-eye');
    togglePassword.classList.toggle('fa-eye-slash');
});

// Form validation and submission