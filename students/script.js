// Theme toggle functionality
function toggleTheme() {
    const html = document.documentElement;
    const themeIcon = document.querySelector('.theme-toggle i');

    if (html.getAttribute('data-theme') === 'dark') {
        html.setAttribute('data-theme', 'light');
        themeIcon.classList.remove('fa-moon');
        themeIcon.classList.add('fa-sun');
    } else {
        html.setAttribute('data-theme', 'dark');
        themeIcon.classList.remove('fa-sun');
        themeIcon.classList.add('fa-moon');
    }

    localStorage.setItem('theme', html.getAttribute('data-theme'));
}

// Initialize theme and other features on page load
document.addEventListener('DOMContentLoaded', () => {
    const savedTheme = localStorage.getItem('theme') || 'dark';
    const themeIcon = document.querySelector('.theme-toggle i');

    document.documentElement.setAttribute('data-theme', savedTheme);

    if (savedTheme === 'light') {
        themeIcon.classList.remove('fa-moon');
        themeIcon.classList.add('fa-sun');
    } else {
        themeIcon.classList.remove('fa-sun');
        themeIcon.classList.add('fa-moon');
    }

    // Add active class to current nav link
    const navLinks = document.querySelectorAll('.nav-link');
    navLinks.forEach(link => {
        link.addEventListener('click', () => {
            navLinks.forEach(l => l.classList.remove('active'));
            link.classList.add('active');
        });
    });

    // Modal functionality
    const calculatorModal = document.getElementById('calculator-modal');
    const gameModal = document.getElementById('game-modal');
    const babaAiModal = document.getElementById('baba-ai-modal');
    const booksModal = document.getElementById('books-modal');
    const openCalculator = document.getElementById('open-calculator');
    const openGame = document.getElementById('open-game');
    const openBabaAi = document.getElementById('open-baba-ai');
    const openBooks = document.getElementById('open-books');
    const closeCalculator = document.getElementById('close-calculator');
    const closeGame = document.getElementById('close-game');
    const closeBabaAi = document.getElementById('close-baba-ai');
    const closeBooks = document.getElementById('close-books');

    openCalculator.addEventListener('click', () => {
        calculatorModal.style.display = 'flex';
        initCalculator();
    });

    openGame.addEventListener('click', () => {
        gameModal.style.display = 'flex';
        if (gameStarted) resetGame();
        initSnakeGame();
    });

    openBabaAi.addEventListener('click', () => {
        babaAiModal.style.display = 'flex';
    });

    openBooks.addEventListener('click', () => {
        booksModal.style.display = 'flex';
    });

    closeCalculator.addEventListener('click', () => {
        calculatorModal.style.display = 'none';
    });

    closeGame.addEventListener('click', () => {
        gameModal.style.display = 'none';
        if (gameInterval) clearInterval(gameInterval);
    });

    closeBabaAi.addEventListener('click', () => {
        babaAiModal.style.display = 'none';
    });

    closeBooks.addEventListener('click', () => {
        booksModal.style.display = 'none';
    });

    // Close modals when clicking outside
    window.addEventListener('click', (e) => {
        if (e.target === calculatorModal) calculatorModal.style.display = 'none';
        if (e.target === gameModal) {
            gameModal.style.display = 'none';
            if (gameInterval) clearInterval(gameInterval);
        }
        if (e.target === babaAiModal) babaAiModal.style.display = 'none';
        if (e.target === booksModal) booksModal.style.display = 'none';
    });

    // Escape key closes modals
    window.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            calculatorModal.style.display = 'none';
            gameModal.style.display = 'none';
            babaAiModal.style.display = 'none';
            booksModal.style.display = 'none';
            if (gameInterval) clearInterval(gameInterval);
        }
    });

    // Initialize additional features
    initResponsiveSidebar();
    createWelcomeNotification();
});

// Calculator functionality
function initCalculator() {
    const calculatorMode = document.getElementById('calculator-mode');
    const basicCalculator = document.getElementById('basic-calculator');
    const simultaneousCalculator = document.getElementById('simultaneous-calculator');
    const quadraticCalculator = document.getElementById('quadratic-calculator');
    const differentiationCalculator = document.getElementById('differentiation-calculator');
    const integrationCalculator = document.getElementById('integration-calculator');

    calculatorMode.addEventListener('change', () => {
        basicCalculator.style.display = 'none';
        simultaneousCalculator.style.display = 'none';
        quadraticCalculator.style.display = 'none';
        differentiationCalculator.style.display = 'none';
        integrationCalculator.style.display = 'none';

        if (calculatorMode.value === 'basic') {
            basicCalculator.style.display = 'block';
        } else if (calculatorMode.value === 'simultaneous') {
            simultaneousCalculator.style.display = 'block';
        } else if (calculatorMode.value === 'quadratic') {
            quadraticCalculator.style.display = 'block';
        } else if (calculatorMode.value === 'differentiation') {
            differentiationCalculator.style.display = 'block';
        } else if (calculatorMode.value === 'integration') {
            integrationCalculator.style.display = 'block';
        }
    });

    // Basic Calculator
    const calculatorScreen = document.querySelector('.calculator-screen');
    const calculatorKeys = document.querySelector('.calculator-keys');
    let currentInput = '0';
    let previousInput = '0';
    let operation = null;
    let resetScreen = false;

    calculatorKeys.addEventListener('click', (e) => {
        if (!e.target.matches('button')) return;

        const key = e.target;
        const keyValue = key.textContent;
        const screenValue = calculatorScreen.value;

        if (key.classList.contains('key-operator')) {
            handleOperator(keyValue);
            return;
        }

        if (key.classList.contains('key-equal')) {
            calculate();
            return;
        }

        if (keyValue === 'C') {
            clear();
            return;
        }

        inputDigit(keyValue);
    });

    function inputDigit(digit) {
        if (resetScreen) {
            calculatorScreen.value = digit;
            resetScreen = false;
        } else {
            calculatorScreen.value = screenValue === '0' ? digit : screenValue + digit;
        }
        currentInput = calculatorScreen.value;
    }

    function handleOperator(nextOperator) {
        const inputValue = parseFloat(currentInput);

        if (operation && resetScreen) {
            operation = nextOperator;
            return;
        }

        if (previousInput === '0') {
            previousInput = inputValue;
        } else if (operation) {
            const result = calculateResult(operation, previousInput, inputValue);
            calculatorScreen.value = String(result);
            previousInput = result;
        }

        resetScreen = true;
        operation = nextOperator;
    }

    function calculate() {
        const inputValue = parseFloat(currentInput);

        if (operation === '+') {
            previousInput = parseFloat(previousInput) + inputValue;
        } else if (operation === '-') {
            previousInput = parseFloat(previousInput) - inputValue;
        } else if (operation === '*') {
            previousInput = parseFloat(previousInput) * inputValue;
        } else if (operation === '/') {
            previousInput = parseFloat(previousInput) / inputValue;
        }

        calculatorScreen.value = String(previousInput);
        resetScreen = true;
        operation = null;
    }

    function clear() {
        calculatorScreen.value = '0';
        currentInput = '0';
        previousInput = '0';
        operation = null;
    }

    // Simultaneous Equations
    document.getElementById('sim-solve').addEventListener('click', () => {
        const a = parseFloat(document.getElementById('sim-a').value);
        const b = parseFloat(document.getElementById('sim-b').value);
        const c = parseFloat(document.getElementById('sim-c').value);
        const d = parseFloat(document.getElementById('sim-d').value);
        const e = parseFloat(document.getElementById('sim-e').value);
        const f = parseFloat(document.getElementById('sim-f').value);

        // Mock solution
        const result = `Mock Solution: x = ${(c * e - b * f) / (a * e - b * d)}, y = ${(a * f - c * d) / (a * e - b * d)}`;
        document.getElementById('sim-result').textContent = result;
    });

    // Quadratic Equations
    document.getElementById('quad-solve').addEventListener('click', () => {
        const a = parseFloat(document.getElementById('quad-a').value);
        const b = parseFloat(document.getElementById('quad-b').value);
        const c = parseFloat(document.getElementById('quad-c').value);

        // Mock solution
        const discriminant = b * b - 4 * a * c;
        let result;
        if (discriminant >= 0) {
            const x1 = (-b + Math.sqrt(discriminant)) / (2 * a);
            const x2 = (-b - Math.sqrt(discriminant)) / (2 * a);
            result = `Mock Solution: x = ${x1}, x = ${x2}`;
        } else {
            result = `Mock Solution: No real roots`;
        }
        document.getElementById('quad-result').textContent = result;
    });

    // Differentiation
    document.getElementById('diff-solve').addEventListener('click', () => {
        const func = document.getElementById('diff-func').value;
        // Mock differentiation
        const result = `Mock Derivative of ${func}: d/dx(${func}) = ...`;
        document.getElementById('diff-result').textContent = result;
    });

    // Integration
    document.getElementById('int-solve').addEventListener('click', () => {
        const func = document.getElementById('int-func').value;
        // Mock integration
        const result = `Mock Integral of ${func}: ∫${func} dx = ... + C`;
        document.getElementById('int-result').textContent = result;
    });
}

// Snake game functionality
let gameStarted = false;
let gameInterval;

function initSnakeGame() {
    const canvas = document.getElementById('snake-game');
    const ctx = canvas.getContext('2d');
    const startBtn = document.getElementById('start-game');
    const resetBtn = document.getElementById('reset-game');
    const scoreDisplay = document.getElementById('game-score');

    const gridSize = 20;
    const gridWidth = canvas.width / gridSize;
    const gridHeight = canvas.height / gridSize;

    let snake = [];
    let food = {};
    let direction = 'right';
    let nextDirection = 'right';
    let score = 0;
    let gameOver = false;
    let gameSpeed = 150;

    function initGame() {
        snake = [
            { x: 5, y: 10 },
            { x: 4, y: 10 },
            { x: 3, y: 10 }
        ];
        direction = 'right';
        nextDirection = 'right';
        score = 0;
        gameOver = false;
        createFood();
        updateScore(0);
        drawGame();
    }

    function createFood() {
        food = {
            x: Math.floor(Math.random() * gridWidth),
            y: Math.floor(Math.random() * gridHeight)
        };
        for (let i = 0; i < snake.length; i++) {
            if (food.x === snake[i].x && food.y === snake[i].y) {
                createFood();
                break;
            }
        }
    }

    function updateScore(newScore) {
        score = newScore;
        scoreDisplay.textContent = `Score: ${score}`;
    }

    function drawGame() {
        ctx.fillStyle = '#000';
        ctx.fillRect(0, 0, canvas.width, canvas.height);

        ctx.fillStyle = '#ff0000';
        ctx.fillRect(food.x * gridSize, food.y * gridSize, gridSize, gridSize);

        snake.forEach((segment, index) => {
            ctx.fillStyle = index === 0 ? '#32cd32' : '#4caf50';
            ctx.fillRect(segment.x * gridSize, segment.y * gridSize, gridSize, gridSize);

            if (index === 0) {
                ctx.fillStyle = '#000';
                if (direction === 'right' || direction === 'left') {
                    ctx.fillRect(segment.x * gridSize + (direction === 'right' ? 15 : 2),
                        segment.y * gridSize + 5, 3, 3);
                    ctx.fillRect(segment.x * gridSize + (direction === 'right' ? 15 : 2),
                        segment.y * gridSize + 12, 3, 3);
                } else {
                    ctx.fillRect(segment.x * gridSize + 5,
                        segment.y * gridSize + (direction === 'down' ? 15 : 2), 3, 3);
                    ctx.fillRect(segment.x * gridSize + 12,
                        segment.y * gridSize + (direction === 'down' ? 15 : 2), 3, 3);
                }
            }

            ctx.strokeStyle = '#003300';
            ctx.strokeRect(segment.x * gridSize, segment.y * gridSize, gridSize, gridSize);
        });

        if (gameOver) {
            ctx.fillStyle = 'rgba(0, 0, 0, 0.75)';
            ctx.fillRect(0, 0, canvas.width, canvas.height);
            ctx.font = '30px Poppins';
            ctx.fillStyle = '#ffffff';
            ctx.textAlign = 'center';
            ctx.fillText('Game Over!', canvas.width / 2, canvas.height / 2);
            ctx.font = '20px Poppins';
            ctx.fillText(`Score: ${score}`, canvas.width / 2, canvas.height / 2 + 40);
            ctx.fillText('Press Start to play again', canvas.width / 2, canvas.height / 2 + 80);
        }
    }

    function updateGame() {
        if (gameOver) return;

        direction = nextDirection;
        const head = { x: snake[0].x, y: snake[0].y };

        switch (direction) {
            case 'right':
                head.x++;
                break;
            case 'left':
                head.x--;
                break;
            case 'up':
                head.y--;
                break;
            case 'down':
                head.y++;
                break;
        }

        if (head.x < 0 || head.x >= gridWidth || head.y < 0 || head.y >= gridHeight) {
            gameOver = true;
            clearInterval(gameInterval);
            drawGame();
            return;
        }

        for (let i = 0; i < snake.length; i++) {
            if (head.x === snake[i].x && head.y === snake[i].y) {
                gameOver = true;
                clearInterval(gameInterval);
                drawGame();
                return;
            }
        }

        if (head.x === food.x && head.y === food.y) {
            snake.unshift(head);
            createFood();
            updateScore(score + 10);
            if (score % 50 === 0) {
                clearInterval(gameInterval);
                gameSpeed = Math.max(50, gameSpeed - 10);
                gameInterval = setInterval(updateGame, gameSpeed);
            }
        } else {
            snake.unshift(head);
            snake.pop();
        }

        drawGame();
    }

    document.addEventListener('keydown', (e) => {
        if (!gameStarted) return;

        switch (e.key) {
            case 'ArrowRight':
                if (direction !== 'left') nextDirection = 'right';
                break;
            case 'ArrowLeft':
                if (direction !== 'right') nextDirection = 'left';
                break;
            case 'ArrowUp':
                if (direction !== 'down') nextDirection = 'up';
                break;
            case 'ArrowDown':
                if (direction !== 'up') nextDirection = 'down';
                break;
        }
    });

    startBtn.addEventListener('click', () => {
        if (gameStarted) return;
        gameStarted = true;
        gameSpeed = 150;
        initGame();
        gameInterval = setInterval(updateGame, gameSpeed);
    });

    resetBtn.addEventListener('click', () => {
        resetGame();
    });

    function resetGame() {
        clearInterval(gameInterval);
        gameStarted = false;
        gameOver = false;
        initGame();
    }

    initGame();
}

// Responsive sidebar toggle
function initResponsiveSidebar() {
    const toggleBtn = document.createElement('button');
    toggleBtn.className = 'sidebar-toggle';
    toggleBtn.innerHTML = '<i class="fas fa-bars"></i>';
    document.body.appendChild(toggleBtn);

    toggleBtn.addEventListener('click', () => {
        document.body.classList.toggle('show-sidebar');
    });
}

// Create a welcome notification
function createWelcomeNotification() {
    const notifications = document.querySelector('.notifications');

    notifications.addEventListener('click', () => {
        let notificationList = document.getElementById('notification-list');

        if (!notificationList) {
            notificationList = document.createElement('div');
            notificationList.id = 'notification-list';
            notificationList.className = 'notification-dropdown';
            notificationList.innerHTML = `
                <div class="notification-item">
                    <div class="notification-icon" style="background: rgba(76, 175, 80, 0.1);">
                        <i class="fas fa-bell text-success"></i>
                    </div>
                    <div class="notification-content">
                        <div class="notification-title">Welcome back!</div>
                        <div class="notification-text">You have 8 pending assignments to complete.</div>
                        <div class="notification-time">Just now</div>
                    </div>
                </div>
                <div class="notification-item">
                    <div class="notification-icon" style="background: rgba(33, 150, 243, 0.1);">
                        <i class="fas fa-calendar-check" style="color: #2196F3;"></i>
                    </div>
                    <div class="notification-content">
                        <div class="notification-title">Research Paper Due</div>
                        <div class="notification-text">Your ENG 201 paper is due in 3 days.</div>
                        <div class="notification-time">2 hours ago</div>
                    </div>
                </div>
                <div class="notification-item">
                    <div class="notification-icon" style="background: rgba(255, 193, 7, 0.1);">
                        <i class="fas fa-star text-warning"></i>
                    </div>
                    <div class="notification-content">
                        <div class="notification-title">Grade Updated</div>
                        <div class="notification-text">Your MTH 301 midterm grade has been posted.</div>
                        <div class="notification-time">Yesterday</div>
                    </div>
                </div>
            `;

            const style = document.createElement('style');
            style.textContent = `
                .notification-dropdown {
                    position: absolute;
                    top: 100%;
                    right: 0;
                    width: 300px;
                    background: var(--card-background);
                    border-radius: var(--border-radius);
                    box-shadow: var(--shadow);
                    z-index: 1000;
                    overflow: hidden;
                    border: 1px solid var(--border-color);
                }

                .notification-item {
                    display: flex;
                    padding: 0.75rem;
                    border-bottom: 1px solid var(--border-color);
                    gap: 0.75rem;
                    cursor: pointer;
                    transition: var(--transition);
                }

                .notification-item:hover {
                    background: var(--input-background);
                }

                .notification-icon {
                    width: 36px;
                    height: 36px;
                    border-radius: 50%;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                }

                .notification-content {
                    flex: 1;
                }

                .notification-title {
                    font-weight: 600;
                    margin-bottom: 0.2rem;
                    font-size: 0.9rem;
                }

                .notification-text {
                    font-size: 0.8rem;
                    color: var(--text-muted);
                    margin-bottom: 0.4rem;
                }

                .notification-time {
                    font-size: 0.75rem;
                    color: var(--text-muted);
                }
            `;

            document.head.appendChild(style);

            const rect = notifications.getBoundingClientRect();
            notificationList.style.top = `${rect.bottom + window.scrollY}px`;
            notificationList.style.right = `${window.innerWidth - rect.right}px`;

            document.body.appendChild(notificationList);

            document.addEventListener('click', (e) => {
                if (!notifications.contains(e.target) && !notificationList.contains(e.target)) {
                    notificationList.remove();
                }
            });
        } else {
            notificationList.remove();
        }
    });
}

// Initialize additional features
document.addEventListener('DOMContentLoaded', () => {
    initResponsiveSidebar();
    createWelcomeNotification();

    const style = document.createElement('style');
    style.textContent = `
        @media (max-width: 1024px) {
            .sidebar {
                transform: translateX(-100%);
                z-index: 2000;
            }

            .main-content {
                margin-left: 0;
            }

            .show-sidebar .sidebar {
                transform: translateX(0);
            }

            .sidebar-toggle {
                position: fixed;
                top: 1rem;
                left: 1rem;
                padding: 0.75rem;
                border-radius: 50%;
                background: var(--primary-color);
                color: white;
                border: none;
                cursor: pointer;
                z-index: 1000;
                display: flex;
                align-items: center;
                justify-content: center;
                width: 3rem;
                height: 3rem;
            }
        }
    `;

    document.head.appendChild(style);
});