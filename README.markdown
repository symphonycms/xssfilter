# Cross-Site Scripting (XSS) Filter

- Version: 1.0
- Author: Symphony Team
- Build Date: 18th October 2010
- Requirements: Symphony 2.*

## Description

Fairly blunt filter to protect Symphony events from common cross-site scripting (XSS) attacks.

## Installation

1. Place the `xssfilter` folder in your Symphony `extensions` directory.
2. Go to _System > Extensions_, select "Cross-Site Scripting (XSS) Filter", choose "Enable" from the with-selected menu, then click Apply.

## Usage

1. Go to _Blueprints > Components_ and click the name of the event whose input you want to filter.
2. In the "Filter Rules" field, select "Filter XSS: Fail if malicious input is detected"
3. Save your event
4. Pirouette

## Notes

The filter, as mentioned above is very strict. It defaults to a high level of protection, and users who want to be more permissive with their input should be savvy enough to filter that input accordingly before rendering the content on the front end.

The filter disallows the following HTML elements: `meta`, `link`, `style`, `script`, `embed`, `object`, `iframe`, `frame`, `frameset`, `title`, and a few other more obscure ones.
