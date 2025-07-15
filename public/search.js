class GlobalSearch {
    constructor() {
        this.searchBox = document.querySelector('.search-box');
        this.searchResults = document.getElementById('searchResults');
        if (this.searchBox && this.searchResults) {
            this.init();
        }
    }

    init() {
        this.searchBox.addEventListener('input', 
            this.debounce(this.handleSearch.bind(this), 300));
        
        document.addEventListener('click', (e) => {
            if (!this.searchBox.contains(e.target) && 
                !this.searchResults.contains(e.target)) {
                this.hideResults();
            }
        });
    }

    async handleSearch(e) {
        const searchTerm = e.target.value.trim();
        
        if (searchTerm.length < 2) {
            this.hideResults();
            return;
        }

        try {
            const response = await fetch(`/api/products/search?q=${encodeURIComponent(searchTerm)}`);
            
            // Check for HTML response first
            const contentType = response.headers.get('content-type');
            if (!contentType || !contentType.includes('application/json')) {
                const text = await response.text();
                if (text.startsWith('<!DOCTYPE')) {
                    throw new Error('Server returned HTML instead of JSON');
                }
                throw new Error(`Unexpected content type: ${contentType}`);
            }

            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.error || `Server error: ${response.status}`);
            }

            this.displayResults(data);
        } catch (error) {
            console.error('Search error:', error);
            this.displayError(error.message);
        }
    }

    displayResults(products) {
        if (!products || products.length === 0) {
            this.searchResults.innerHTML = '<div class="no-results">No products found</div>';
            this.searchResults.style.display = 'block';
            return;
        }

        this.searchResults.innerHTML = products.map(product => `
            <a href="/product-detail?name=${encodeURIComponent(product.name)}" class="search-result-item">
                <img src="${product.imagepath || 'ps/placeholder.png'}" alt="${product.name}">
                <div class="search-result-info">
                    <h4>${product.name}</h4>
                    <p>${product.category}</p>
                    <span>${product.currency}${product.display_price}</span>
                </div>
            </a>
        `).join('');

        this.searchResults.style.display = 'block';
    }

    displayError(message) {
        this.searchResults.innerHTML = `
            <div class="search-error">
                ${message || 'Search service unavailable. Please try again later.'}
            </div>
        `;
        this.searchResults.style.display = 'block';
    }

    hideResults() {
        this.searchResults.style.display = 'none';
    }

    debounce(func, wait) {
        let timeout;
        return function(...args) {
            clearTimeout(timeout);
            timeout = setTimeout(() => func.apply(this, args), wait);
        };
    }
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    new GlobalSearch();
});