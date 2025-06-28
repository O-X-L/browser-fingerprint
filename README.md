# Client-Side Browser-Fingerprinting

This is an example on how to generate a simple browser-fingerprint for your Web-Clients which you can use for traffic analysis.

Test it: [fingerprint.oxl.app](https://fingerprint.oxl.app)

**Be aware:**

* As we have to set this fingerprint as cookie or request-header - the user could manually modify or replace it.
* If attackers are aware of this they are able to work around it. (*p.e. randomize the hash*)
* Clients with noscript or bots without JS-capabilities will not send any fingerprint.

You have to think of those facts when you are analyzing your request-logs.

----

You might want to combine it with **server-side client-fingerprinting** techniques like JA4. See:

* [O-X-L/haproxy-ja4](https://github.com/O-X-L/haproxy-ja4)
* [O-X-L/haproxy-ja4h](https://github.com/O-X-L/haproxy-ja4h)
* [O-X-L/haproxy-ja3n](https://github.com/O-X-L/haproxy-ja3n)

**More information**:

* [OXL Docs](https://docs.o-x-l.com/waf/2_fingerprinting.html)
* [Mozilla - Browser Fingerpinting](https://developer.mozilla.org/en-US/docs/Glossary/Fingerprinting)
* [github.com/niespodd](https://github.com/niespodd/browser-fingerprinting)
* [TCP/OS Fingerpinting](https://incolumitas.com/2021/03/13/tcp-ip-fingerprinting-for-vpn-and-proxy-detection/)
* [fingerprintjs](https://fingerprint.com/blog/browser-fingerprinting-techniques/)

----

## Example

We utilize the OSS [thumbmarkjs](https://github.com/thumbmarkjs/thumbmarkjs) library.

### Result

* **Linux Laptop Chromium 136.x** => `linux_chrome_1536x864_347e44db7f27cb8c236bec1ae84791ce`
* **Linux Laptop Chromium 136.x private tab** => `linux_chrome_1536x864_347e44db7f27cb8c236bec1ae84791ce`
* **Linux Laptop Firefox 128.x** => `linux_firefox_1536x864_957bc354b66b5f2def573500c8c0f466`
* **Linux Laptop Firefox 128.x private tab** => `linux_firefox_1536x864_957bc354b66b5f2def573500c8c0f466`

### Minimal Code

```html
<script src="https://cdn.jsdelivr.net/npm/@thumbmarkjs/thumbmarkjs/dist/thumbmark.umd.js"></script>
<script>...</script>
```

```js
ThumbmarkJS.setOption('logging', false);

// NOTE: some browsers and private-modes will change those values - if you don't care about that or want more 'uniqueness' you can remove the entries
ThumbmarkJS.setOption('exclude', ['webgl', 'canvas', 'permissions', 'audio.sampleHash']);

function screenSize() {
    let [w, h] = [screen.width, screen.height];
    // handle device rotation if mobile
    if (navigator.maxTouchPoints > 0 && window.matchMedia("(orientation: landscape)").matches) {
        w = screen.height;
        h = screen.width;
    }
    return Promise.resolve({width: w, height: h});
}
ThumbmarkJS.includeComponent('size', screenSize);

/**
 * Generates a minimal cleartext key. This information can be useful to categorize requests.
 * @returns {string}
 */
function buildBrowserFingerprintKey(c) {
    let s = c.system.platform.split(' ')[0].toLowerCase();

    if (navigator.userAgent.match(/iPhone|iPad/i)) {
        s = 'ios';
    } else if (navigator.userAgent.includes('Android')) {
        s = 'android';
    }

    const k = [
        s,
        c.system.browser.name.toLowerCase(),
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
