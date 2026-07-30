// Initialize theme immediately to prevent flash
(function() {
    const savedTheme = localStorage.getItem('theme') ||
                      (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    document.documentElement.setAttribute('data-theme', savedTheme);
})();

function setTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('theme', theme);
    const selector = document.querySelector('.theme-selector');
    if (selector) {
        selector.value = theme;
    }
}

document.addEventListener('DOMContentLoaded', () => {
    const savedTheme = document.documentElement.getAttribute('data-theme');
    const themeOptions = {
        light: 'Light',
        dark: 'Dark',
        hacker: 'Hacker',
        modern: 'Cyborg',
        darkly: 'Darkly'
    };

    const select = document.createElement('select');
    select.className = 'theme-selector';
    select.setAttribute('aria-label', 'Theme');

    for (const [value, label] of Object.entries(themeOptions)) {
        const option = document.createElement('option');
        option.value = value;
        option.textContent = label;
        select.appendChild(option);
    }

    select.value = savedTheme in themeOptions ? savedTheme : 'light';
    select.onchange = (event) => setTheme(event.target.value);

    const bar = document.querySelector('.theme-bar');
    if (bar) {
        bar.appendChild(select);
    } else {
        document.body.appendChild(select);
    }
});
