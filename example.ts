// npm install @thumbmarkjs/thumbmarkjs
import {
    getFingerprint, getFingerprintData,
    setOption as setFingerprintOption,
    includeComponent as includeFingerprintComponent,
} from '@thumbmarkjs/thumbmarkjs';

setFingerprintOption('logging', false);

// NOTE: some browsers and private-modes will change those values - if you don't care about that or want more 'uniqueness' you can remove the entries
setFingerprintOption('exclude', ['webgl', 'canvas', 'permissions', 'audio.sampleHash']);

function screenSize() {
    let [w, h] = [screen.width, screen.height];
    // handle device rotation if mobile
    if (navigator.maxTouchPoints > 0 && window.matchMedia("(orientation: landscape)").matches) {
        w = screen.height;
        h = screen.width;
    }
    return Promise.resolve({width: w, height: h});
}
includeFingerprintComponent('size', screenSize);

/**
 * Generates a minimal cleartext key. This information can be useful to categorize requests.
 */
function buildBrowserFingerprintKey(c: any) : string {
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
 */
async function generateBrowserFingerprint() : Promise<string> {
    try {
        const c = await getFingerprintData();
        const h = await getFingerprint();
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
