const GuacamoleLite = require('guacamole-lite');

const websocketOptions = {
    port: process.env.PORT ? parseInt(process.env.PORT) : 8080
};

const guacdOptions = {
    host: process.env.GUACD_HOST || 'guacd',
    port: process.env.GUACD_PORT ? parseInt(process.env.GUACD_PORT) : 4822
};

const clientOptions = {
    crypt: {
        cypher: 'AES-256-CBC',
        key: process.env.GUACAMOLE_SHARED_KEY || 'guacamole_shared_secret_key_32c'
    },
    log: {
        level: 'VERBOSE'
    }
};

console.log('Starting Guacamole-Lite server with config:', {
    websocketOptions,
    guacdOptions,
    clientOptions: {
        crypt: {
            cypher: clientOptions.crypt.cypher,
            key: '***' + clientOptions.crypt.key.slice(-4)
        },
        log: clientOptions.log
    }
});

const guacServer = new GuacamoleLite(websocketOptions, guacdOptions, clientOptions);

guacServer.on('error', (client, err) => {
    console.error('Guacamole client error:', err);
});
