(function(e){function t(t){for(var r,a,u=t[0],d=t[1],i=t[2],l=0,s=[];l<u.length;l++)a=u[l],Object.prototype.hasOwnProperty.call(c,a)&&c[a]&&s.push(c[a][0]),c[a]=0;for(r in d)Object.prototype.hasOwnProperty.call(d,r)&&(e[r]=d[r]);b&&b(t);while(s.length)s.shift()();return o.push.apply(o,i||[]),n()}function n(){for(var e,t=0;t<o.length;t++){for(var n=o[t],r=!0,a=1;a<n.length;a++){var u=n[a];0!==c[u]&&(r=!1)}r&&(o.splice(t--,1),e=d(d.s=n[0]))}return e}var r={},a={app:0},c={app:0},o=[];function u(e){return d.p+"js/"+({}[e]||e)+"."+{"chunk-12427005":"fac8bbb3","chunk-2d22d612":"1c0f41f3","chunk-2d0e26e8":"ec1f52fb","chunk-2d21805e":"d4d38a26","chunk-5046447e":"e9a04fa8","chunk-2d0cc063":"beedafdb"}[e]+".js"}function d(t){if(r[t])return r[t].exports;var n=r[t]={i:t,l:!1,exports:{}};return e[t].call(n.exports,n,n.exports,d),n.l=!0,n.exports}d.e=function(e){var t=[],n={"chunk-5046447e":1};a[e]?t.push(a[e]):0!==a[e]&&n[e]&&t.push(a[e]=new Promise((function(t,n){for(var r="css/"+({}[e]||e)+"."+{"chunk-12427005":"31d6cfe0","chunk-2d22d612":"31d6cfe0","chunk-2d0e26e8":"31d6cfe0","chunk-2d21805e":"31d6cfe0","chunk-5046447e":"64577053","chunk-2d0cc063":"31d6cfe0"}[e]+".css",c=d.p+r,o=document.getElementsByTagName("link"),u=0;u<o.length;u++){var i=o[u],l=i.getAttribute("data-href")||i.getAttribute("href");if("stylesheet"===i.rel&&(l===r||l===c))return t()}var s=document.getElementsByTagName("style");for(u=0;u<s.length;u++){i=s[u],l=i.getAttribute("data-href");if(l===r||l===c)return t()}var b=document.createElement("link");b.rel="stylesheet",b.type="text/css",b.onload=t,b.onerror=function(t){var r=t&&t.target&&t.target.src||c,o=new Error("Loading CSS chunk "+e+" failed.\n("+r+")");o.code="CSS_CHUNK_LOAD_FAILED",o.request=r,delete a[e],b.parentNode.removeChild(b),n(o)},b.href=c;var h=document.getElementsByTagName("head")[0];h.appendChild(b)})).then((function(){a[e]=0})));var r=c[e];if(0!==r)if(r)t.push(r[2]);else{var o=new Promise((function(t,n){r=c[e]=[t,n]}));t.push(r[2]=o);var i,l=document.createElement("script");l.charset="utf-8",l.timeout=120,d.nc&&l.setAttribute("nonce",d.nc),l.src=u(e);var s=new Error;i=function(t){l.onerror=l.onload=null,clearTimeout(b);var n=c[e];if(0!==n){if(n){var r=t&&("load"===t.type?"missing":t.type),a=t&&t.target&&t.target.src;s.message="Loading chunk "+e+" failed.\n("+r+": "+a+")",s.name="ChunkLoadError",s.type=r,s.request=a,n[1](s)}c[e]=void 0}};var b=setTimeout((function(){i({type:"timeout",target:l})}),12e4);l.onerror=l.onload=i,document.head.appendChild(l)}return Promise.all(t)},d.m=e,d.c=r,d.d=function(e,t,n){d.o(e,t)||Object.defineProperty(e,t,{enumerable:!0,get:n})},d.r=function(e){"undefined"!==typeof Symbol&&Symbol.toStringTag&&Object.defineProperty(e,Symbol.toStringTag,{value:"Module"}),Object.defineProperty(e,"__esModule",{value:!0})},d.t=function(e,t){if(1&t&&(e=d(e)),8&t)return e;if(4&t&&"object"===typeof e&&e&&e.__esModule)return e;var n=Object.create(null);if(d.r(n),Object.defineProperty(n,"default",{enumerable:!0,value:e}),2&t&&"string"!=typeof e)for(var r in e)d.d(n,r,function(t){return e[t]}.bind(null,r));return n},d.n=function(e){var t=e&&e.__esModule?function(){return e["default"]}:function(){return e};return d.d(t,"a",t),t},d.o=function(e,t){return Object.prototype.hasOwnProperty.call(e,t)},d.p="",d.oe=function(e){throw console.error(e),e};var i=window["webpackJsonp"]=window["webpackJsonp"]||[],l=i.push.bind(i);i.push=t,i=i.slice();for(var s=0;s<i.length;s++)t(i[s]);var b=l;o.push([0,"chunk-vendors"]),n()})({0:function(e,t,n){e.exports=n("cd49")},9374:function(e,t,n){},cd49:function(e,t,n){"use strict";n.r(t);var r=n("7a23");const a={id:"app"},c={class:"navbar navbar-expand navbar-dark bg-dark"},o=Object(r["createTextVNode"])("SBOM Service"),u={class:"navbar-nav mr-auto"},d={class:"nav-item"},i=Object(r["createTextVNode"])("风险看板"),l={class:"nav-item"},s=Object(r["createTextVNode"])("软件成分查询"),b={class:"nav-item"},h=Object(r["createTextVNode"])("开源软件反向追溯链");function f(e,t,n,f,p,m){const v=Object(r["resolveComponent"])("router-link"),k=Object(r["resolveComponent"])("router-view");return Object(r["openBlock"])(),Object(r["createElementBlock"])("div",a,[Object(r["createElementVNode"])("nav",c,[Object(r["createVNode"])(v,{to:"/",class:"navbar-brand"},{default:Object(r["withCtx"])(()=>[o]),_:1}),Object(r["createElementVNode"])("div",u,[Object(r["createElementVNode"])("li",d,[Object(r["createVNode"])(v,{to:"/sbomDashboard",class:"nav-link"},{default:Object(r["withCtx"])(()=>[i]),_:1})]),Object(r["createElementVNode"])("li",l,[Object(r["createVNode"])(v,{to:"/sbomPackages",class:"nav-link"},{default:Object(r["withCtx"])(()=>[s]),_:1})]),Object(r["createElementVNode"])("li",b,[Object(r["createVNode"])(v,{to:"/sbomTraceChain",class:"nav-link"},{default:Object(r["withCtx"])(()=>[h]),_:1})])])]),Object(r["createElementVNode"])("div",null,[Object(r["createVNode"])(k)])])}var p=Object(r["defineComponent"])({name:"App"}),m=(n("d013"),n("6b0d")),v=n.n(m);const k=v()(p,[["render",f]]);var O=k,g=(n("4989"),n("ab8b"),n("c3a1")),j=(n("d9b6"),n("6605"));const y=[{path:"/",redirect:"sbomPackages"},{path:"/sbomDashboard",name:"sbomDashboard",component:()=>n.e("chunk-2d0cc063").then(n.bind(null,"4bba"))},{path:"/sbomPackages",name:"sbomPackages",component:()=>Promise.all([n.e("chunk-12427005"),n.e("chunk-2d22d612"),n.e("chunk-2d0e26e8")]).then(n.bind(null,"7f58"))},{path:"/sbomTraceChain",name:"sbomTraceChain",component:()=>Promise.all([n.e("chunk-12427005"),n.e("chunk-2d22d612"),n.e("chunk-2d21805e")]).then(n.bind(null,"c8e8"))},{path:"/packageDetails/:id",name:"package-details",component:()=>Promise.all([n.e("chunk-12427005"),n.e("chunk-5046447e")]).then(n.bind(null,"a4e1"))}],w=Object(j["a"])({history:Object(j["b"])(),routes:y});var N=w;Object(r["createApp"])(O).use(N).use(g["a"]).mount("#app")},d013:function(e,t,n){"use strict";n("9374")}});
//# sourceMappingURL=app.99a2490c.js.map