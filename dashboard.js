document.addEventListener('DOMContentLoaded', function() {
    setInterval(function() {
        fetch('/stats/json')
            .then(response => response.json())
            .then(data => console.log('Stats refreshed:', data))
            .catch(err => console.error('Refresh failed:', err));
    }, 60000);
});
