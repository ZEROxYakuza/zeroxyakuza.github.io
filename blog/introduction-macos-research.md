---
title: "SQL Injection Avanzado: Bypassing WAF"
date: "15 Mayo 2026"
readTime: "10 min"
tags: ["Web Hacking", "SQL Injection", "WAF Bypass"]
excerpt: "Exploro técnicas avanzadas de SQL Injection para evadir firewalls..."
---

# Título del artículo

Tu contenido aquí en Markdown...

## Subtítulo

Más contenido...

````bash
# Código de ejemplo
echo "Hola mundo"
````

## Ejemplo de Post Completo

Archivo: `blog/sql-injection-bypass.md`

````markdown
---
title: "SQL Injection Avanzado: Bypassing WAF con técnicas alternativas"
date: "15 Mayo 2026"
readTime: "10 min"
tags: ["Web Hacking", "SQL Injection", "WAF Bypass"]
excerpt: "Exploro técnicas avanzadas de SQL Injection para evadir firewalls de aplicaciones web modernos."
---

# SQL Injection Avanzado

## Introducción

Los Web Application Firewalls (WAF) se han convertido en una defensa estándar...

## Técnicas de Ofuscación

### 1. Case Manipulation

```sql
' UNION SELECT NULL,NULL--
' uNiOn SeLeCt NULL,NULL--
```

### 2. Comentarios Inline

```sql
' UNION/**/SELECT/**/NULL,NULL--
```

## Conclusión

La evasión de WAF requiere creatividad...
````

## Alternativa: Posts embebidos en JavaScript

Si no quieres usar archivos .md separados, puedes definir los posts directamente en el HTML dentro de un array de JavaScript (ya incluido en el portfolio que te proporcioné).

Busca en el HTML la sección:

````javascript
const blogPosts = [
    {
        title: "Título del post",
        date: "15 Mayo 2026",
        readTime: "10 min",
        tags: ["Tag1", "Tag2"],
        excerpt: "Resumen corto...",
        content: `# Markdown content here...`
    },
    // Añade más posts aquí
];
````

## Ventajas de cada método

### Archivos .md separados (Requiere servidor)
- ✅ Más fácil de editar
- ✅ Mejor organización
- ✅ Versionable con Git
- ❌ Necesita servidor web (no funciona con file://)

### Posts en JavaScript (Funciona localmente)
- ✅ Funciona abriendo el HTML directamente
- ✅ Todo en un solo archivo
- ❌ Más difícil de mantener
- ❌ Archivo HTML más grande

## Opción recomendada para ti

Ya que quieres algo funcional inmediatamente, te he preparado el portfolio con **3 posts de ejemplo ya embebidos en JavaScript**.

Solo abre el archivo HTML y:
1. Verás 3 posts de ejemplo sobre:
   - SQL Injection y bypass de WAF
   - Kerberoasting en Active Directory  
   - SSRF to RCE en Cloud

2. Para añadir más posts, edita el array `blogPosts` en el JavaScript del HTML

3. Para personalizar los posts existentes, simplemente modifica el contenido en Markdown dentro de cada objeto del array

¡Y listo! Tu blog está funcional sin necesidad de servidor.
