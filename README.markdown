# Cross-Site Scripting (XSS) Filter

## Description

Protect yourself against XSS and XSRF attacks in form submissions.

## Installation

1. Place the `xssfilter` folder in your Symphony `extensions` directory.
2. Go to _System > Extensions_, select "Cross-Site Scripting (XSS) Filter", choose "Enable" from the with-selected menu, then click Apply.

## Usage

### XSS

1. Go to _Blueprints > Components_ and click the name of the event whose input you want to filter.
2. In the "Filters" section, select "Filter XSS: Fail if malicious input is detected"
3. Save your event
4. Pirouette

Additionally, the XSS Filter can be used directly in your extensions via `Extension_XSSFilter::detectXSS($string)` which takes a string and returns boolean if XSS is detected.

#### Notes

The XSS Filter, as mentioned above is very strict. It defaults to a high level of protection, and users who want to be more permissive with their input should be savvy enough to filter that input accordingly before rendering the content on the front end.

The filter disallows the following HTML elements: `meta`, `link`, `style`, `script`, `embed`, `object`, `iframe`, `frame`, `frameset`, `title`, and a few other more obscure ones.

### XSRF

1. Go to _Blueprints > Components_ and click the name of the event whose input you want to filter.
2. In the "Filters" section, select "Validate XSRF: Ensure request was passed with a XSRF token"
3. Save your event
4. In your POST request, ensure `$_POST['xsrf']` is set with a valid token (available via params `{$cookie-xsrf-token}`)

Additionally, the XSRF Filter can be used directly in your extensions via `XSRF::validateToken($token)` which takes a string and returns boolean if it is not valid.

