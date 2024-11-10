self.addEventListener('push', function (event) {
    console.log('Push message received:', event);

    try {
        let notificationData = {};

        if (event.data) {
            notificationData = event.data.json();
            console.log('Notification data:', notificationData);
        }

        // Send message to all clients
        event.waitUntil(
            clients.matchAll({
                type: 'window',
                includeUncontrolled: true
            }).then(function(clientList) {
                clientList.forEach(client => {
                    client.postMessage({
                        type: 'SHOW_ALERT',
                        title: notificationData.title || 'Default Title',
                        body: notificationData.body || 'Default message body',
                        icon: notificationData.icon || '/static/img/icon.png',
                        url: notificationData.url || '/',
                        ...notificationData
                    });
                });
            })
        );
    } catch (error) {
        console.error('Error showing notification:', error);
    }
});

self.addEventListener('notificationclick', function (event) {
    console.log('Notification clicked:', event);

    event.notification.close();

    // Handle notification click
    if (event.action === 'open' || !event.action) {
        // Get the notification data
        const data = event.notification.data;
        const url = data.url || '/';

        // Open or focus the appropriate window/tab
        event.waitUntil(
            clients.matchAll({
                type: 'window',
                includeUncontrolled: true
            }).then(function (clientList) {
                // Check if there's already a window/tab open
                for (let client of clientList) {
                    if (client.url === url && 'focus' in client) {
                        return client.focus();
                    }
                }
                // If no window/tab is open, open a new one
                if (clients.openWindow) {
                    return clients.openWindow(url);
                }
            })
        );
    }
});

self.addEventListener('notificationclose', function (event) {
    console.log('Notification closed:', event);
});

// Handle service worker installation
self.addEventListener('install', function (event) {
    console.log('Service Worker installed');
    self.skipWaiting();
});

// Handle service worker activation
self.addEventListener('activate', function (event) {
    console.log('Service Worker activated');
    event.waitUntil(clients.claim());
});