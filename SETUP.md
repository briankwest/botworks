# Deploying a Flask Application on Dokku

This guide provides step-by-step instructions to deploy a Flask application on Dokku, set up PostgreSQL and Redis services, and enable Let's Encrypt for SSL.

## Prerequisites

1. **Dokku Installation**: Ensure Dokku is installed on your server. You can follow the [official Dokku installation guide](http://dokku.viewdocs.io/dokku/getting-started/installation/) if it's not already installed.

2. **Domain Setup**: Make sure your domain is pointed to your server's IP address.

## Step-by-Step Deployment

### 1. Create a New Dokku App
```bash
dokku apps:create your-app-name
```


### 2. Set Up PostgreSQL

1. **Install the PostgreSQL Plugin** (if not already installed):

   ```bash
   sudo dokku plugin:install https://github.com/dokku/dokku-postgres.git postgres
   ```

2. **Create a PostgreSQL Service**:

   ```bash
   dokku postgres:create your-app-name-db
   ```

3. **Link the PostgreSQL Service to Your App**:

   ```bash
   dokku postgres:link your-app-name-db your-app-name
   ```

### 3. Set Up Redis

1. **Install the Redis Plugin** (if not already installed):

   ```bash
   sudo dokku plugin:install https://github.com/dokku/dokku-redis.git redis
   ```

2. **Create a Redis Service**:

   ```bash
   dokku redis:create your-app-name-redis
   ```

3. **Link the Redis Service to Your App**:

   ```bash
   dokku redis:link your-app-name-redis your-app-name
   ```

### 4. Configure Environment Variables

Set any necessary environment variables, such as `SECRET_KEY`, using:

```bash
dokku config:set your-app-name SECRET_KEY='your-secret-key'
```


### 5. Deploy Your Application

1. **Add Dokku Remote**:

   ```bash
   git remote add dokku dokku@your-server-ip:your-app-name
   ```

2. **Push Your Code to Dokku**:

   ```bash
   git push dokku main
   ```

   Replace `main` with your branch name if different.

### 6. Enable Let's Encrypt

1. **Install the Let's Encrypt Plugin** (if not already installed):

   ```bash
   sudo dokku plugin:install https://github.com/dokku/dokku-letsencrypt.git
   ```

2. **Set the Domain for Your App**:

   ```bash
   dokku domains:set your-app-name your-domain.com
   ```

3. **Enable Let's Encrypt**:

   ```bash
   dokku letsencrypt:enable your-app-name
   ```

4. **Set Up Automatic Renewal**:

   ```bash
   dokku letsencrypt:cron-job --add
   ```

## Additional Configuration

- **Static Files**: Ensure your Flask app is configured to serve static files correctly. You might need to adjust your `app.py` to set the `static_folder` path if not already done.

- **Debug Mode**: Make sure to set `DEBUG=False` in production for security reasons.

- **Database Migrations**: If you use Flask-Migrate, run migrations after deployment:

  ```bash
  dokku run your-app-name flask db upgrade
  ```

By following these steps, you should have your Flask application running on Dokku with PostgreSQL and Redis services, secured with Let's Encrypt SSL.
