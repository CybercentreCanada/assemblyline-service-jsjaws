/*
    browser.js - simulates web browser like environment
*/

util_log("Preparing sandbox to emulate Browser environment (default = IE11).");
_browser_documents = [];

const { atob, btoa } = require("abab");

location = _proxy({
    _name: "location",
    _props: {
        "href": "http://example.com/?search",
        "hostname": "example.com",
        "search": "?search",
        "host": "example.com",
        "pathname": "C:/script.js"
    },
    replace: function (n) {
        util_log(this._name + ".replace(" + n + ")");
        this._props["href"] = n;
    },
    protocol: function (n) {
        util_log(this._name + ".protocol(" + n + ")");
    }
})
location.toString = () => { return "location" }
for (let k in location._props) {
    _defineProperty(location, k, location._props);
}

screen = _proxy({
    availHeight: 1080,
    availLeft: 78,
    availTop: 0,
    availWidth: 1842,
    colorDepth: 24,
    height: 1080,
    orientation: { // ScreenOrientation
        angle: 0,
        onchange: null,
        type: "landscape-primary"
    },
    pixelDepth: 24,
    width: 1920
})
screen.toString = () => { return "screen" }


_setInterval_calls = [];
_setTimeout_calls = [];
window = _proxy(new function () {
    this.id = _object_id++;
    this._name = "window[" + this.id + "]";
    //this._props = {
    //    "userAgent" : "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
    //    "chrome" : false,
    //    "vendor" : "Microsoft"
    //};
    //for (var k in this._props) {
    //    _defineProperty(this, k, this._props);
    //}
    this.eval = eval;
    this.settimeout = function () {
        util_log(this._name + ".setTimeout(" + Array.prototype.slice.call(arguments, 0).join(",") + ")");
        _setTimeout_calls[_setTimeout_calls.length] = arguments[0].toString();
        //util_log(typeof arguments[0]);
        return _setTimeout.apply(this, Array.prototype.slice.call(arguments, 0));
    }
    this.cleartimeout = function () {
        util_log(this._name + ".clearTimeout(" + Array.prototype.slice.call(arguments, 0).join(",") + ")");
        _clearTimeout.apply(this, Array.prototype.slice.call(arguments, 0));
    }
    this.scrollby = function (x, y) {
        util_log(this._name + ".scrollBy(" + Array.prototype.slice.call(arguments, 0).join(",") + ")");
    }
    this.setinterval = function () {
        util_log(this._name + ".setInterval(" + Array.prototype.slice.call(arguments, 0).join(",") + ")");
        _setInterval_calls[_setInterval_calls.length] = arguments[0].toString();
        //util_log(typeof arguments[0]);
        return _setInterval.apply(this, Array.prototype.slice.call(arguments, 0));
    }
    this.clearinterval = function () {
        util_log(this._name + ".clearInterval(" + Array.prototype.slice.call(arguments, 0).join(",") + ")");
        _clearInterval.apply(this, Array.prototype.slice.call(arguments, 0));
    }
    this.settimeoutsync = function () {
        util_log(this._name + ".setTimeout(" + Array.prototype.slice.call(arguments, 0).join(",") + ")");
        _setTimeout_calls[_setTimeout_calls.length] = arguments[0].toString();
        //util_log(typeof arguments[0]);
        return arguments[0].apply(this, Array.prototype.slice.call(arguments, 1));
    }
    this.setintervalsync = function () {
        util_log(this._name + ".setInterval(" + Array.prototype.slice.call(arguments, 0).join(",") + ")");
        _setInterval_calls[_setInterval_calls.length] = arguments[0].toString();
        //util_log(typeof arguments[0]);
        return arguments[0].apply(this, Array.prototype.slice.call(arguments, 1));
    }

    this.clearintervalsync = function () {
        util_log(this._name + ".clearInterval(" + Array.prototype.slice.call(arguments, 0).join(",") + ")");
    }
    this.onload = function () { }
    this.onunload = function () { }
    this.jstiming = function () { }
    this.jstiming.load = function () { }
    this.jstiming.load.tick = function () { }
    this.platform = function () { }
    this.gapi = function () { }
    this.console = function () { }
    this.crypto = function () {
        util_log(arguments);
        util_log(this._name + ".crypto(" + arguments + ")");
    }
    this.gapi_onload = function () { }
    this.__GOOGLEAPIS = function () { }
    this.___gu = function () { }
    this.___jsl = function () { }
    this.___gcfg = function () { }
    this.ga = function () { }
    this.navigator = this;
    // Defaulting to Microsoft for the time being
    this.appName = "Microsoft";
    this.atob = atob;
    this.btoa = btoa;
    this._location = location,
        Object.defineProperty(this, "location", {
            get: function (n) {
                return this._location;
            },
            set: function (n) {
                util_log("document.location.set(" + n + ")");
                this._location.href = n;
            }
        })
    this.top = function () { }
    this.self = function () {
        this.location = function () {
            util_log("get location" + arguments)
        }
    }
    this.platform = "Windows";
    this.frames = function () {
        this.odbFrame = "";
    }
    this.addEventListener = function (n) {
        util_log(this._name + ".addEventListener(" + n + ")")
    }
});

window.toString = () => { return "window" }
window.XMLHttpRequest = true;


for (let k in _browser_api) {
    if (_browser_api.hasOwnProperty(k))
        if (typeof _browser_api[k] !== 'undefined') {
            window[k] = _browser_api[k];
        }
}

window.Element = Element;
window.HTMLElement = HTMLElement;
window.Node = Node;
window.msSaveOrOpenBlob = async function (content, filename) {
    util_log("msSaveOrOpenBlob(" + content + ", " + filename + ")")
    if (content.constructor.name == "Blob") {
        content = Buffer.from(await content.arrayBuffer())
    }
    _wscript_saved_files[filename] = content;
}
setTimeout = window.setTimeout.bind(window);
setInterval = window.setInterval.bind(window);
clearInterval = window.clearInterval.bind(window);
clearTimeout = window.clearInterval.bind(window);

navigator = window;

Document = _proxy(function () {
    this.id = _object_id++;
    this._name = "document[" + this.id + "]";
    this._content = "";
    this._elements = [];
    this.getelementsbytagname = function (n) {
        let ret = []
        util_log(this._name + ".getElementsByTagName(" + n + ")");
        for (i = 0; i < this._elements.length; i++) {
            let e = this._elements[i];
            if (e.elementName.toLowerCase() === n.toLowerCase()) {
                ret[ret.length] = e;
            }
        }
        util_log(this._name + ".getElementsByTagName(" + n + ") ... " + ret.length + " found");
        return ret;
    };
    this.getelementsbyclassname = function (n) {
        let ret = []
        util_log(this._name + ".getElementsByClassName(" + n + ")");
        for (i = 0; i < this._elements.length; i++) {
            let e = this._elements[i];
            if (e.class.toLowerCase() === n.toLowerCase()) {
                ret[ret.length] = e;
            }
        }
        util_log(this._name + ".getElementsByClassName(" + n + ") ... " + ret.length + " found");
        return ret;
    };
    this.getelementbyid = function (n) {
        util_log(this._name + ".getElementById(" + n + ")");
        if (n === undefined) {
            return this._elements[0];
        }
        for (i = 0; i < this._elements.length; i++) {
            let e = this._elements[i];
            if (("" + e._id).toLowerCase() === n.toLowerCase()) {
                util_log(this._name + ".getElementById(" + n + ") => " + e._name);
                return e;
            }
        }
        util_log(this._name + ".getElementById(" + n + ") => null");
        // return null;
        // Bad hack here because it doesn't really matter
        return this._elements[0];
    };
    this.createelement = function (n) {
        util_log(this._name + ".createElement(" + n + ")");
        let e;
        if (n.toLowerCase() === "iframe") {
            e = new HTMLIFrameElement();
        } else if (n.toLowerCase() === "style") {
            e = new Style();
        } else {
            e = new Element(n);
        }
        this._elements[this._elements.length] = e;
        return e;
    };
    this.createtextnode = function (n) {
        util_log(this._name + ".createTextNode(" + n + ")");
        return new Element(n);
    };
    this.createstylesheet = function (n) {
        util_log(this._name + ".createStyleSheet(" + n + ")");
        return this.createelement("style");
    };
    this.write = function (c) {
        util_log(this._name + ".write(content) " + c.length + " bytes");
        util_log("=> '" + c + "'");
        _content = c;
        _browser_documents[_browser_documents.length] = c;
    };
    this.writeln = function (c) {
        util_log(this._name + ".writeln(content) " + c.length + " bytes");
        util_log("=> '" + c + "'");
        _content = c;
        _browser_documents[_browser_documents.length] = c;
    };
    this._addElementById = function (id, content) {
        let e = new Element("div");
        e.id = _object_id;
        e.innerHTML = content;
        this._elements[this._elements.length] = e;
    };
    this._addElementByClass = function (cls, content) {
        let e = new Element("div");
        e.class = cls;
        e.innerHTML = content;
        this._elements[this._elements.length] = e;
    };
    this._props = {
        "body": undefined,
        "referrer": "http://example.com/",
        "cookie": "",
        "namespaces": undefined
    };
    this._location = location;
    for (let k in this._props) {
        _defineProperty(this, k, this._props);
    }
    this.documentelement = this.createelement("html");
    this.body = this.createelement("body");
    this.head = this.createelement("head");
    this.namespaces = new Collection();
    this.documentelement.appendchild(this.head);
    this.documentelement.appendchild(this.body);
    this.childNodes = function (c) {
        return c._elements;
    };
    this.defaultView = this.window;
    this.nodeType = function (c) {
        util_log(this._name + ".nodeType");
        if (typeof c === Element) {
            return 1;
        }
        else if (typeof c === Attr) {
            return 2;
        }
        else if (typeof c === Text) {
            return 3;
        }
        else if (typeof c === Comment) {
            return 8;
        }
    };
    this.onmouseover = function () { }
    this.onclick = function () { }
    this.onmouseout = function () { }
    this.documentMode = function () { }
    this.compatMode = function () { }
    this.scripts = function (n) {
        util_log("Script: " + n);
    }
    this.readyState = function (n) {
        util_log("readyState(" + n + ")");
    }
    this.addEventListener = function (n) {
        util_log("addEventListener(" + n + ")");
    }
    this.attachEvent = function (n) {
        util_log("attachEvent(" + n + ")");
    }
    this.URL = location;
    this.evaluate = function (n) {
        util_log(this._name + ".evaluate(" + n + ")");
    }

})
Document.prototype = Object.create(Node.prototype);
Document.prototype.constructor = Document;
Document.toString = Document.toJSON = () => { return "Document" }

document = _proxy(new Document());
document.toString = () => { return "document" }
window.document = document;
window.URL = URL;

$ = function (thing) {
    util_log("$(" + thing + ")");
    if (thing == this) {
        thing = this.id;
    }
    return document.getElementById(thing);
};

Object.defineProperty(document, "location", {
    get: function () {
        util_log("document.location.get()");
        return this._location;
    },
    set: function (n) {
        util_log("document.location.set(" + n + ")");
        this._location.href = n;
    }
})

let Image = function (w, h) {
    Element.call(this, "Image");
    util_log("Image(" + w + ", " + h + ")");

    this._width = w;
    this._height = h;
    _defineSingleProperty(this, "width", "_width");
    _defineSingleProperty(this, "height", "_height");
}
Image.prototype = Object.create(Element.prototype);
Image.prototype.constructor = Image;
