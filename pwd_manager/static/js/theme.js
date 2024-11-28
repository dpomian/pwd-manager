// Initialize theme immediately to prevent flash
(function() {
    const savedTheme = localStorage.getItem('theme') || 
                      (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    document.documentElement.setAttribute('data-theme', savedTheme);
})();

function toggleTheme() {
    const currentTheme = document.documentElement.getAttribute('data-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    
    document.documentElement.setAttribute('data-theme', newTheme);
    localStorage.setItem('theme', newTheme);
    
    const buttonText = newTheme === 'dark' ? '☀️ Light Mode' : '🌙 Dark Mode';
    document.querySelector('.theme-toggle').textContent = buttonText;
}

// Initialize theme toggle button on page load
document.addEventListener('DOMContentLoaded', () => {
    const savedTheme = document.documentElement.getAttribute('data-theme');
    const buttonText = savedTheme === 'dark' ? '☀️ Light Mode' : '🌙 Dark Mode';
    const button = document.createElement('button');
    button.className = 'theme-toggle';
    button.textContent = buttonText;
    button.onclick = toggleTheme;
    document.body.appendChild(button);
});
