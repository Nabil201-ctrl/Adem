// Theme Toggle Function
function toggleTheme() {
    const html = document.documentElement;
    const currentTheme = html.getAttribute('data-theme');
    const newTheme = currentTheme === 'light' ? 'dark' : 'light';
    
    html.setAttribute('data-theme', newTheme);
    localStorage.setItem('theme', newTheme);
    
    // Update theme toggle icon
    const themeToggle = document.querySelector('.theme-toggle i');
    if (themeToggle) {
        themeToggle.className = newTheme === 'light' ? 'fas fa-moon' : 'fas fa-sun';
    }
}

// Sidebar Toggle Function
function toggleSidebar() {
    const sidebar = document.querySelector('.sidebar');
    const overlay = document.querySelector('.sidebar-overlay');
    
    if (sidebar && overlay) {
        sidebar.classList.toggle('active');
        overlay.style.display = sidebar.classList.contains('active') ? 'block' : 'none';
    }
}

// Close sidebar when clicking outside
function closeSidebar() {
    const sidebar = document.querySelector('.sidebar');
    const overlay = document.querySelector('.sidebar-overlay');
    
    if (sidebar && overlay) {
        sidebar.classList.remove('active');
        overlay.style.display = 'none';
    }
}

// Notification Functions
function toggleNotifications() {
    const popup = document.getElementById('notificationPopup');
    if (popup) {
        popup.style.display = popup.style.display === 'none' ? 'block' : 'none';
    }
}

function closeNotifications() {
    const popup = document.getElementById('notificationPopup');
    if (popup) {
        popup.style.display = 'none';
    }
}

// Deadline Modal Functions
function openDeadlineModal(isExtend = false) {
    const modal = document.getElementById('deadlineModal');
    const title = document.getElementById('deadlineModalTitle');
    const saveBtn = document.getElementById('saveDeadlineBtn');
    
    if (modal && title && saveBtn) {
        modal.style.display = 'flex';
        title.textContent = isExtend ? 'Extend Registration Deadline' : 'Set Registration Deadline';
        saveBtn.textContent = isExtend ? 'Extend' : 'Save';
        
        // Set minimum date to today
        const now = new Date();
        const minDate = now.toISOString().slice(0, 16);
        document.getElementById('deadlineInput').min = minDate;
    }
}

function closeDeadlineModal() {
    const modal = document.getElementById('deadlineModal');
    if (modal) {
        modal.style.display = 'none';
        document.getElementById('deadlineForm').reset();
        document.getElementById('deadlineError').textContent = '';
    }
}

// Toast Notification Function
function showToast(message, type = 'info') {
    const toast = document.getElementById('toast');
    if (toast) {
        toast.textContent = message;
        toast.className = `custom-toast ${type} show`;
        
        setTimeout(() => {
            toast.classList.remove('show');
        }, 3000);
    }
}

// Logout Function
function logout() {
    // Clear any stored data
    localStorage.removeItem('userToken');
    localStorage.removeItem('userData');
    
    // Show confirmation
    if (confirm('Are you sure you want to logout?')) {
        // Redirect to login page
        window.location.href = './index.html';
    }
}

// Search Function
function handleSearch() {
    const searchInput = document.getElementById('searchInput');
    const searchTerm = searchInput.value.toLowerCase();
    
    // This would typically filter the data
    console.log('Searching for:', searchTerm);
    // Add your search logic here
}

// Sample Data Management
let studentsData = [
    {
        id: 1,
        name: "John Doe",
        email: "john.doe@example.com",
        matricNumber: "CSC/2021/001",
        phone: "08012345678",
        faculty: "Computer Science",
        level: "300",
        interviewDate: "2024-01-15",
        status: "pending"
    },
    {
        id: 2,
        name: "Jane Smith",
        email: "jane.smith@example.com",
        matricNumber: "ENG/2021/002",
        phone: "08087654321",
        faculty: "Engineering",
        level: "200",
        interviewDate: "2024-01-16",
        status: "pending"
    }
];

let activities = [
    {
        icon: "fas fa-user-plus",
        text: "New student registration",
        time: "2 hours ago"
    },
    {
        icon: "fas fa-check-circle",
        text: "Payment verified for Room 101",
        time: "4 hours ago"
    },
    {
        icon: "fas fa-calendar",
        text: "Interview scheduled",
        time: "6 hours ago"
    }
];

// Load Dashboard Data
function loadDashboardData() {
    // Update statistics
    document.getElementById('totalStudents').textContent = studentsData.length;
    document.getElementById('occupiedRooms').textContent = '12';
    document.getElementById('monthlyRevenue').textContent = '₦450,000';
    document.getElementById('pendingRequests').textContent = studentsData.filter(s => s.status === 'pending').length;
    
    // Load pending requests table
    loadPendingRequests();
    
    // Load activities
    loadActivities();
    
    // Load notifications
    loadNotifications();
}

// Load Pending Requests
function loadPendingRequests() {
    const tableBody = document.getElementById('pendingRequestsTable');
    const mobileView = document.getElementById('pendingRequestsMobile');
    
    if (!tableBody || !mobileView) return;
    
    const pendingStudents = studentsData.filter(student => student.status === 'pending');
    
    // Desktop table view
    tableBody.innerHTML = pendingStudents.map(student => `
        <tr>
            <td>${student.name}</td>
            <td>${student.email}</td>
            <td class="hide-mobile">${student.matricNumber}</td>
            <td class="hide-mobile">${student.phone}</td>
            <td class="hide-mobile">${student.faculty}</td>
            <td class="hide-mobile">${student.level}</td>
            <td class="hide-mobile">${student.interviewDate}</td>
            <td><span class="status ${student.status}">${student.status}</span></td>
            <td>
                <div class="table-actions">
                    <button class="action-button" onclick="approveStudent(${student.id})">
                        <i class="fas fa-check"></i> Approve
                    </button>
                    <button class="action-button" onclick="rejectStudent(${student.id})" style="background: var(--danger-color);">
                        <i class="fas fa-times"></i> Reject
                    </button>
                </div>
            </td>
        </tr>
    `).join('');
    
    // Mobile card view
    mobileView.innerHTML = pendingStudents.map(student => `
        <div class="student-card">
            <p><strong>Name:</strong> ${student.name}</p>
            <p><strong>Email:</strong> ${student.email}</p>
            <p><strong>Matric:</strong> ${student.matricNumber}</p>
            <p><strong>Phone:</strong> ${student.phone}</p>
            <p><strong>Faculty:</strong> ${student.faculty}</p>
            <p><strong>Level:</strong> ${student.level}</p>
            <p><strong>Interview:</strong> ${student.interviewDate}</p>
            <p><strong>Status:</strong> <span class="status ${student.status}">${student.status}</span></p>
            <div class="table-actions">
                <button class="action-button" onclick="approveStudent(${student.id})">
                    <i class="fas fa-check"></i> Approve
                </button>
                <button class="action-button" onclick="rejectStudent(${student.id})" style="background: var(--danger-color);">
                    <i class="fas fa-times"></i> Reject
                </button>
            </div>
        </div>
    `).join('');
}

// Load Activities
function loadActivities() {
    const activityList = document.getElementById('activityList');
    if (!activityList) return;
    
    activityList.innerHTML = activities.map(activity => `
        <div class="activity-item">
            <div class="activity-icon">
                <i class="${activity.icon}"></i>
            </div>
            <div class="activity-details">
                <div class="activity-text">${activity.text}</div>
                <div class="activity-time">${activity.time}</div>
            </div>
        </div>
    `).join('');
}

// Load Notifications
function loadNotifications() {
    const notificationList = document.getElementById('notificationList');
    const notificationCount = document.getElementById('notificationCount');
    
    if (!notificationList || !notificationCount) return;
    
    const notifications = [
        { title: "New Registration", message: "John Doe submitted application", time: "2 hours ago", unread: true },
        { title: "Payment Received", message: "Room 101 payment verified", time: "4 hours ago", unread: false }
    ];
    
    const unreadCount = notifications.filter(n => n.unread).length;
    notificationCount.textContent = unreadCount;
    notificationCount.style.display = unreadCount > 0 ? 'block' : 'none';
    
    if (notifications.length === 0) {
        notificationList.innerHTML = '<div class="empty-notifications">No notifications</div>';
    } else {
        notificationList.innerHTML = notifications.map(notification => `
            <div class="notification-item ${notification.unread ? 'unread' : ''}">
                <div class="notification-title">
                    <strong>${notification.title}</strong>
                    <span class="notification-time">${notification.time}</span>
                </div>
                <div class="notification-message">${notification.message}</div>
            </div>
        `).join('');
    }
}

// Student Actions
function approveStudent(studentId) {
    const student = studentsData.find(s => s.id === studentId);
    if (student) {
        student.status = 'active';
        loadDashboardData();
        showToast('Student approved successfully!', 'success');
    }
}

function rejectStudent(studentId) {
    if (confirm('Are you sure you want to reject this student?')) {
        const student = studentsData.find(s => s.id === studentId);
        if (student) {
            student.status = 'inactive';
            loadDashboardData();
            showToast('Student rejected.', 'error');
        }
    }
}

// Deadline Management
function setDeadline() {
    openDeadlineModal(false);
}

function extendDeadline() {
    openDeadlineModal(true);
}

// Initialize Dashboard
document.addEventListener('DOMContentLoaded', function() {
    // Hide loading screen
    setTimeout(() => {
        document.getElementById('loading').style.display = 'none';
    }, 1000);
    
    // Initialize theme
    const savedTheme = localStorage.getItem('theme') || 'dark';
    document.documentElement.setAttribute('data-theme', savedTheme);
    
    // Update theme toggle icon based on current theme
    const themeToggle = document.querySelector('.theme-toggle i');
    if (themeToggle) {
        themeToggle.className = savedTheme === 'light' ? 'fas fa-moon' : 'fas fa-sun';
    }
    
    // Load dashboard data
    loadDashboardData();
    
    // Event Listeners
    const searchInput = document.getElementById('searchInput');
    if (searchInput) {
        searchInput.addEventListener('input', handleSearch);
    }
    
    // Notification click handler
    const notificationIcon = document.querySelector('.notifications');
    if (notificationIcon) {
        notificationIcon.addEventListener('click', toggleNotifications);
    }
    
    // Close notifications when clicking outside
    const closeNotificationsBtn = document.getElementById('closeNotifications');
    if (closeNotificationsBtn) {
        closeNotificationsBtn.addEventListener('click', closeNotifications);
    }
    
    // Deadline form handler
    const deadlineForm = document.getElementById('deadlineForm');
    if (deadlineForm) {
        deadlineForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const deadline = document.getElementById('deadlineInput').value;
            if (deadline) {
                const deadlineDate = new Date(deadline);
                document.getElementById('registrationDeadline').textContent = deadlineDate.toLocaleDateString();
                closeDeadlineModal();
                showToast('Deadline set successfully!', 'success');
            }
        });
    }
    
    // Deadline button handlers
    const setDeadlineBtn = document.getElementById('setDeadlineBtn');
    const extendDeadlineBtn = document.getElementById('extendDeadlineBtn');
    
    if (setDeadlineBtn) {
        setDeadlineBtn.addEventListener('click', () => openDeadlineModal(false));
    }
    
    if (extendDeadlineBtn) {
        extendDeadlineBtn.addEventListener('click', () => openDeadlineModal(true));
    }
    
    // Close modal when clicking outside
    const modal = document.getElementById('deadlineModal');
    if (modal) {
        modal.addEventListener('click', function(e) {
            if (e.target === modal) {
                closeDeadlineModal();
            }
        });
    }
    
    // Handle window resize
    window.addEventListener('resize', function() {
        if (window.innerWidth > 1024) {
            closeSidebar();
        }
    });
    
    // Prevent sidebar from closing when clicking inside it
    const sidebar = document.querySelector('.sidebar');
    if (sidebar) {
        sidebar.addEventListener('click', function(e) {
            e.stopPropagation();
        });
    }
});

// Global error handler
window.addEventListener('error', function(e) {
    console.error('Dashboard Error:', e.error);
    showToast('An error occurred. Please refresh the page.', 'error');
});