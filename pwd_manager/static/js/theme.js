// Initialize theme immediately to prevent flash
(function() {
    const savedTheme = localStorage.getItem('theme') || 
                      (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    document.documentElement.setAttribute('data-theme', savedTheme);
})();

function toggleTheme() {
    const currentTheme = document.documentElement.getAttribute('data-theme');
    let newTheme;
    
    switch(currentTheme) {
        case 'light':
            newTheme = 'dark';
            break;
        case 'dark':
            newTheme = 'hacker';
            break;
        default:
            newTheme = 'light';
    }
    
    document.documentElement.setAttribute('data-theme', newTheme);
    localStorage.setItem('theme', newTheme);
    
    const icons = {
        'light': '🌙 Dark Mode',
        'dark': '💻 Hacker Mode',
        'hacker': '☀️ Light Mode'
    };
    
    document.querySelector('.theme-toggle').textContent = icons[newTheme];
}

// Initialize theme toggle button on page load
document.addEventListener('DOMContentLoaded', () => {
    const savedTheme = document.documentElement.getAttribute('data-theme');
    const icons = {
        'light': '🌙 Dark Mode',
        'dark': '💻 Hacker Mode',
        'hacker': '☀️ Light Mode'
    };
    
    const button = document.createElement('button');
    button.className = 'theme-toggle';
    button.textContent = icons[savedTheme];
    button.onclick = toggleTheme;
    document.body.appendChild(button);
});
