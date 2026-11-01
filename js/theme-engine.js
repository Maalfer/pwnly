/*
 * Motor de plantillas de los temas de Pwnly.
 *
 * Sintaxis (subconjunto tipo Mustache/Handlebars, sin dependencias):
 *   {{ruta.al.valor}}      interpolación con escape HTML
 *   {{{ruta.al.valor}}}    interpolación SIN escapar (HTML ya renderizado)
 *   {{#each findings}} ... {{this.title}} ... {{/each}}   bucle sobre un array
 *   {{#if finding.poc}} ... {{else}} ... {{/if}}          condicional (truthy)
 *   {{#unless finding.poc}} ... {{/unless}}               condicional negado
 *   {{@index}} / {{@index1}} / {{@first}} / {{@last}}     metadatos dentro de #each
 *   {{! comentario }}                                     se ignora al renderizar
 *
 * Dentro de un #each, "this" (o ".") es el elemento actual; las rutas sin
 * coincidencia en el elemento actual se buscan hacia fuera (contexto padre),
 * igual que en Mustache.
 *
 * Expuesto como objeto global `ThemeEngine` (sin módulos, consistente con el
 * resto de la SPA).
 */
(function (global) {
    'use strict';

    function escapeHtml(str) {
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function tokenize(src) {
        const tokens = [];
        let i = 0;
        const n = src.length;
        while (i < n) {
            const nextTag = src.indexOf('{{', i);
            if (nextTag === -1) {
                tokens.push({ type: 'text', value: src.slice(i) });
                break;
            }
            if (nextTag > i) tokens.push({ type: 'text', value: src.slice(i, nextTag) });

            if (src.slice(nextTag, nextTag + 3) === '{{{') {
                const close = src.indexOf('}}}', nextTag + 3);
                if (close === -1) { tokens.push({ type: 'text', value: src.slice(nextTag) }); break; }
                tokens.push({ type: 'var', expr: src.slice(nextTag + 3, close).trim(), raw: true });
                i = close + 3;
                continue;
            }

            const close = src.indexOf('}}', nextTag + 2);
            if (close === -1) { tokens.push({ type: 'text', value: src.slice(nextTag) }); break; }
            const inner = src.slice(nextTag + 2, close).trim();
            i = close + 2;

            if (inner.startsWith('#each ')) tokens.push({ type: 'each-open', expr: inner.slice(6).trim() });
            else if (inner === '/each') tokens.push({ type: 'each-close' });
            else if (inner.startsWith('#if ')) tokens.push({ type: 'if-open', expr: inner.slice(4).trim() });
            else if (inner === '/if') tokens.push({ type: 'if-close' });
            else if (inner.startsWith('#unless ')) tokens.push({ type: 'unless-open', expr: inner.slice(8).trim() });
            else if (inner === '/unless') tokens.push({ type: 'unless-close' });
            else if (inner === 'else') tokens.push({ type: 'else' });
            else if (inner.startsWith('!')) tokens.push({ type: 'comment' });
            else if (inner) tokens.push({ type: 'var', expr: inner, raw: false });
        }
        return tokens;
    }

    function pushChild(parent, child) {
        if (parent.type === 'if' && parent._inElse) parent.elseChildren.push(child);
        else parent.children.push(child);
    }

    function buildAst(tokens) {
        const root = { type: 'root', children: [] };
        const stack = [root];

        tokens.forEach((tok) => {
            const top = stack[stack.length - 1];
            switch (tok.type) {
                case 'text':
                    if (tok.value) pushChild(top, { type: 'text', value: tok.value });
                    break;
                case 'var':
                    pushChild(top, { type: 'var', expr: tok.expr, raw: tok.raw });
                    break;
                case 'comment':
                    break;
                case 'each-open': {
                    const node = { type: 'each', expr: tok.expr, children: [] };
                    pushChild(top, node);
                    stack.push(node);
                    break;
                }
                case 'each-close':
                    if (stack.length > 1 && stack[stack.length - 1].type === 'each') stack.pop();
                    break;
                case 'if-open': {
                    const node = { type: 'if', expr: tok.expr, children: [], elseChildren: null, _inElse: false };
                    pushChild(top, node);
                    stack.push(node);
                    break;
                }
                case 'else': {
                    const node = stack[stack.length - 1];
                    if (node && node.type === 'if') { node.elseChildren = []; node._inElse = true; }
                    break;
                }
                case 'if-close':
                    if (stack.length > 1 && stack[stack.length - 1].type === 'if') stack.pop();
                    break;
                case 'unless-open': {
                    const node = { type: 'unless', expr: tok.expr, children: [] };
                    pushChild(top, node);
                    stack.push(node);
                    break;
                }
                case 'unless-close':
                    if (stack.length > 1 && stack[stack.length - 1].type === 'unless') stack.pop();
                    break;
            }
        });
        return root;
    }

    function resolvePath(path, stack) {
        if (path === '.' || path === 'this') return stack[stack.length - 1];
        const parts = path.split('.');
        for (let i = stack.length - 1; i >= 0; i--) {
            const scope = stack[i];
            if (scope !== null && typeof scope === 'object' && parts[0] in scope) {
                let val = scope;
                for (const p of parts) {
                    if (val === null || val === undefined) return undefined;
                    val = val[p];
                }
                return val;
            }
        }
        return undefined;
    }

    function isTruthy(val) {
        if (Array.isArray(val)) return val.length > 0;
        return !!val;
    }

    function renderNodes(nodes, stack, metaStack) {
        let out = '';
        for (const node of nodes) {
            if (node.type === 'text') { out += node.value; continue; }

            if (node.type === 'var') {
                let val;
                if (node.expr.startsWith('@')) {
                    const meta = metaStack[metaStack.length - 1];
                    val = meta ? meta[node.expr] : undefined;
                } else {
                    val = resolvePath(node.expr, stack);
                }
                if (val === undefined || val === null) val = '';
                out += node.raw ? String(val) : escapeHtml(val);
                continue;
            }

            if (node.type === 'each') {
                const arr = resolvePath(node.expr, stack);
                if (Array.isArray(arr)) {
                    arr.forEach((item, idx) => {
                        stack.push(item);
                        metaStack.push({ '@index': idx, '@index1': idx + 1, '@first': idx === 0, '@last': idx === arr.length - 1 });
                        out += renderNodes(node.children, stack, metaStack);
                        metaStack.pop();
                        stack.pop();
                    });
                }
                continue;
            }

            if (node.type === 'if') {
                const truthy = isTruthy(resolvePath(node.expr, stack));
                if (truthy) out += renderNodes(node.children, stack, metaStack);
                else if (node.elseChildren) out += renderNodes(node.elseChildren, stack, metaStack);
                continue;
            }

            if (node.type === 'unless') {
                if (!isTruthy(resolvePath(node.expr, stack))) out += renderNodes(node.children, stack, metaStack);
                continue;
            }
        }
        return out;
    }

    function render(template, context) {
        if (typeof template !== 'string' || !template) return '';
        const ast = buildAst(tokenize(template));
        return renderNodes(ast.children, [context || {}], []);
    }

    global.ThemeEngine = { render, escapeHtml };
})(window);
