# Client-Side Browser-Fingerprinting

This is an example on how to generate a simple browser-fingerprint for your Web-Clients which you can use for traffic analysis.

**Be aware:**

* As we have to set this fingerprint as cookie or request-header - the user could manually modify or replace it.
* If attackers are aware of this they are able to work around it. (*p.e. randomize the hash*)
* Clients with noscript or bots without JS-capabilities will not send any fingerprint.

You have to think of those facts when you are analyzing your request-logs.

You might want to combine it with server-side client-fingerprinting techniques like JA4. See:

* [O-X-L/haproxy-ja4](https://github.com/O-X-L/haproxy-ja4)
* [O-X-L/haproxy-ja4h](https://github.com/O-X-L/haproxy-ja4h)
* [O-X-L/haproxy-ja3n](https://github.com/O-X-L/haproxy-ja3n)

----

## Example

We utilize the OSS [thumbmarkjs](https://github.com/thumbmarkjs/thumbmarkjs) library.

```html
<script src="https://cdn.jsdelivr.net/npm/@thumbmarkjs/thumbmarkjs/dist/thumbmark.umd.js"></script>
<script>...</script>
```

```js
ThumbmarkJS.setOption('logging', false);

// NOTE: some browsers and private-modes will change those values - if you don't care about that or want more 'uniqueness' you can remove the entries
ThumbmarkJS.setOption('exclude', ['webgl', 'canvas', 'permissions', 'audio.sampleHash']);

function screenSize() {
  return Promise.resolve({width: screen.width, height: screen.height});
}
ThumbmarkJS.includeComponent('size', screenSize);

/**
 * Generates a minimal cleartext key. This information can be useful to categorize requests.
 * @returns {string}
 */
function buildBrowserFingerprintKey(c) {
    k = [
        c.system.platform.split(' ')[0],
        c.system.browser.name,
        `${c.size.width}x${c.size.height}`,
    ];
    if (c.screen.is_touchscreen) {
        k.push('touch');
    };
    return k.join('_');
}

/**
 * Generates the full browser fingerprint string.
 * @returns {Promise<string>} A Promise that resolves with the fingerprint string.
 */
async function generateBrowserFingerprint() {
    try {
        const c = await ThumbmarkJS.getFingerprintData();
        const h = await ThumbmarkJS.getFingerprint();
        return `${buildBrowserFingerprintKey(c)}_${h}`;
    } catch (error) {
        console.error('Error generating fingerprint:', error);
        // Re-throw the error so the caller can handle it
        throw error;
    }
}

/* replace with your implementation: */
async function setFingerprintCookie() {
    const fp = await generateBrowserFingerprint();
    console.log(fp);
    document.cookie = `fingerprint=${fp}`;
}

async function performSomeRequest() {
    const fp = await generateBrowserFingerprint();
    const headers = {
        'X-Fingerprint': fp,
        'Content-Type': 'application/json'
    };
    console.log(headers);
}

setFingerprintCookie();
performSomeRequest();
```
