FROM php:8.2-fpm

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    libpng-dev \
    libonig-dev \
    libxml2-dev \
    zip \
    unzip \
    libzip-dev \
    && docker-php-ext-install pdo_mysql mbstring exif pcntl bcmath gd zip \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install Composer
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

# Custom PHP config (OPcache tuning)
COPY docker/php.ini /usr/local/etc/php/conf.d/99-custom.ini

# Set working directory
WORKDIR /var/www

# Copy project files
COPY . /var/www

# Install dependencies
RUN composer install --no-dev --optimize-autoloader --no-interaction 2>/dev/null || true

# Set permissions
RUN chown -R www-data:www-data /var/www/storage /var/www/bootstrap/cache 2>/dev/null || true

# Cache Laravel config, routes & views
RUN php artisan config:cache 2>/dev/null || true \
    && php artisan route:cache 2>/dev/null || true \
    && php artisan view:cache 2>/dev/null || true

EXPOSE 9000
CMD ["php-fpm"]
