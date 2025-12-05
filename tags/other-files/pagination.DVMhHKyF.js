import{c as z,j as i,a as c}from"./utils.U0exV3tK.js";import{r as m}from"./index.Dy6lLLXr.js";/**
 * @license lucide-react v0.469.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const V=e=>e.replace(/([a-z0-9])([A-Z])/g,"$1-$2").toLowerCase(),N=(...e)=>e.filter((t,n,a)=>!!t&&t.trim()!==""&&a.indexOf(t)===n).join(" ").trim();/**
 * @license lucide-react v0.469.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */var E={xmlns:"http://www.w3.org/2000/svg",width:24,height:24,viewBox:"0 0 24 24",fill:"none",stroke:"currentColor",strokeWidth:2,strokeLinecap:"round",strokeLinejoin:"round"};/**
 * @license lucide-react v0.469.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const L=m.forwardRef(({color:e="currentColor",size:t=24,strokeWidth:n=2,absoluteStrokeWidth:a,className:s="",children:r,iconNode:u,...x},h)=>m.createElement("svg",{ref:h,...E,width:t,height:t,stroke:e,strokeWidth:a?Number(n)*24/Number(t):n,className:N("lucide",s),...x},[...u.map(([o,l])=>m.createElement(o,l)),...Array.isArray(r)?r:[r]]));/**
 * @license lucide-react v0.469.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const p=(e,t)=>{const n=m.forwardRef(({className:a,...s},r)=>m.createElement(L,{ref:r,iconNode:t,className:N(`lucide-${V(e)}`,a),...s}));return n.displayName=`${e}`,n};/**
 * @license lucide-react v0.469.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const $=p("ChevronLeft",[["path",{d:"m15 18-6-6 6-6",key:"1wnfg3"}]]);/**
 * @license lucide-react v0.469.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const A=p("ChevronRight",[["path",{d:"m9 18 6-6-6-6",key:"mthhwq"}]]);/**
 * @license lucide-react v0.469.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const _=p("Ellipsis",[["circle",{cx:"12",cy:"12",r:"1",key:"41hilf"}],["circle",{cx:"19",cy:"12",r:"1",key:"1wjl8i"}],["circle",{cx:"5",cy:"12",r:"1",key:"1pcz8c"}]]),y=e=>typeof e=="boolean"?`${e}`:e===0?"0":e,k=z,O=(e,t)=>n=>{var a;if(t?.variants==null)return k(e,n?.class,n?.className);const{variants:s,defaultVariants:r}=t,u=Object.keys(s).map(o=>{const l=n?.[o],v=r?.[o];if(l===null)return null;const d=y(l)||y(v);return s[o][d]}),x=n&&Object.entries(n).reduce((o,l)=>{let[v,d]=l;return d===void 0||(o[v]=d),o},{}),h=t==null||(a=t.compoundVariants)===null||a===void 0?void 0:a.reduce((o,l)=>{let{class:v,className:d,...w}=l;return Object.entries(w).every(C=>{let[j,g]=C;return Array.isArray(g)?g.includes({...r,...x}[j]):{...r,...x}[j]===g})?[...o,v,d]:o},[]);return k(e,u,h,n?.class,n?.className)},R=O("inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-md text-sm font-medium transition-all disabled:pointer-events-none disabled:opacity-50 [&_svg]:pointer-events-none [&_svg:not([class*='size-'])]:size-4 shrink-0 [&_svg]:shrink-0 outline-none focus-visible:border-ring focus-visible:ring-ring/50 focus-visible:ring-[3px] aria-invalid:ring-destructive/20 dark:aria-invalid:ring-destructive/40 aria-invalid:border-destructive",{variants:{variant:{default:"bg-primary text-primary-foreground hover:bg-primary/90",destructive:"bg-destructive text-white hover:bg-destructive/90 focus-visible:ring-destructive/20 dark:focus-visible:ring-destructive/40 dark:bg-destructive/60",outline:"border bg-background hover:bg-muted hover:text-foreground dark:bg-input/30 dark:border-input dark:hover:bg-input/50",muted:"bg-muted text-foreground hover:bg-muted/80",ghost:"hover:bg-muted hover:text-foreground dark:hover:bg-muted/50",link:"text-primary underline-offset-4 hover:underline"},size:{default:"h-9 px-4 py-2 has-[>svg]:px-3",sm:"h-8 rounded-md gap-1.5 px-3 has-[>svg]:px-2.5",lg:"h-10 rounded-md px-6 has-[>svg]:px-4",icon:"size-9"}},defaultVariants:{variant:"default",size:"default"}});function P({className:e,...t}){return i.jsx("nav",{role:"navigation","aria-label":"pagination","data-slot":"pagination",className:c("mx-auto flex w-full justify-center",e),...t})}function I({className:e,...t}){return i.jsx("ul",{"data-slot":"pagination-content",className:c("flex flex-row items-center gap-1",e),...t})}function f({...e}){return i.jsx("li",{"data-slot":"pagination-item",...e})}function b({className:e,isActive:t,isDisabled:n,size:a="icon",...s}){return i.jsx("a",{"aria-current":t?"page":void 0,"data-slot":"pagination-link","data-active":t,"data-disabled":n,className:c(R({variant:t?"outline":"ghost",size:a}),n&&"pointer-events-none opacity-50",e),...s})}function B({className:e,isDisabled:t,...n}){return i.jsxs(b,{"aria-label":"Go to previous page",size:"default",className:c("gap-1 px-2.5 sm:pl-2.5",e),isDisabled:t,...n,children:[i.jsx($,{}),i.jsx("span",{className:"hidden sm:block",children:"Previous"})]})}function G({className:e,isDisabled:t,...n}){return i.jsxs(b,{"aria-label":"Go to next page",size:"default",className:c("gap-1 px-2.5 sm:pr-2.5",e),isDisabled:t,...n,children:[i.jsx("span",{className:"hidden sm:block",children:"Next"}),i.jsx(A,{})]})}function K({className:e,...t}){return i.jsxs("span",{"aria-hidden":!0,"data-slot":"pagination-ellipsis",className:c("flex size-9 items-center justify-center",e),...t,children:[i.jsx(_,{className:"size-4"}),i.jsx("span",{className:"sr-only",children:"More pages"})]})}const D=({currentPage:e,totalPages:t,baseUrl:n})=>{const a=Array.from({length:t},(r,u)=>u+1),s=r=>r===1?n:`${n}${r}`;return i.jsx(P,{children:i.jsxs(I,{className:"flex-wrap",children:[i.jsx(f,{children:i.jsx(B,{href:e>1?s(e-1):void 0,isDisabled:e===1})}),a.map(r=>i.jsx(f,{children:i.jsx(b,{href:s(r),isActive:r===e,children:r})},r)),t>5&&i.jsx(f,{children:i.jsx(K,{})}),i.jsx(f,{children:i.jsx(G,{href:e<t?s(e+1):void 0,isDisabled:e===t})})]})})};export{D as default};
