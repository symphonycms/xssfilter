<?php

    /**
     * XSS protection function for HTML context only
     * @usecases
     * <title>use this function if output reflects here or as a content of any HTML tag.</title>
     * e.g.,  <span>use this function if output reflects here</span>
     * e.g., <div>use this function if output reflects here</div>
     * @description
     * Sanitize/Filter < and > so that attacker can not leverage them for JavaScript execution.
     * @author Ashar Javed
     * @Link https://twitter.com/soaj1664ashar
     * @demo http://xssplaygroundforfunandlearn.netai.net/final.html
     */
    function htmlContextCleaner($input) {
        $bad_chars = array("<", ">");

        $safe_chars = array("&lt;", "&gt;");

        $output = str_replace($bad_chars, $safe_chars, $input);

        return stripslashes($output);
    }

    /**
     * XSS protection function for script context only
     * @usecases
     * @double quoted case e.g.,
     * <script> var searchquery = "use this function if output reflects here"; </script>
     * @single quoted case e.g.,
     * <script> var searchquery = 'use this function if output reflects here'; </script>
     * @description
     * Sanitize/Filter meta or control characters that attacker may use to break the context e.g.,
     * "; confirm(1); " OR '; prompt(1); // OR </script><script>alert(1)</script>
     * \ and % are filtered because they may break the page e.g., \n or %0a
     * & is sanitized because of complex or nested context (if in use)
     * @author Ashar Javed
     * @Link https://twitter.com/soaj1664ashar
     * @demo http://xssplaygroundforfunandlearn.netai.net/final.html
     */
    function scriptContextCleaner($input) {
        $bad_chars = array("\"", "<", "'", "\\\\", "%", "&");

        $safe_chars = array("&quot;", "&lt;", "&apos;", "&bsol;", "&percnt;", "&amp;");

        $output = str_replace($bad_chars, $safe_chars, $input);

        return stripslashes($output);
    }

    /**
     * XSS protection function for an attribute context only
     * @usecases
     * @double quoted case e.g.,
     * <div class="use this function if output reflects here">attribute context</div>
     * In above example class attribute have been used but it can be any like id or alt etc.
     * @single quoted case e.g.,
     * <input type='text' value='use this function if output reflects here'>
     * @description
     * Sanitize/Filter meta or control characters that attacker may use to break the context e.g.,
     * "onmouseover="alert(1) OR 'onfocus='confirm(1) OR ``onmouseover=prompt(1)
     * back-tick i.e., `` is filtered because old IE browsers treat it as a valid separator.
     * @author Ashar Javed
     * @Link https://twitter.com/soaj1664ashar
     * @demo http://xssplaygroundforfunandlearn.netai.net/final.html
     */
    function attributeContextCleaner($input) {
        $bad_chars = array("\"", "'",  "`");

        $safe_chars = array("&quot;", "&apos;", "&grave;");

        $output = str_replace($bad_chars, $safe_chars, $input);

        return stripslashes($output);
    }

    /**
     * XSS protection function for style context only
     * @usecases
     * @double quoted case e.g.,
     * <span style="use this function if output reflects here"></span>
     * @single quoted case e.g.,
     * <div style='use this function if output reflects here'></div>
     * OR <style>use this function if output reflects here</style>
     * @description
     * Sanitize/Filter meta or control characters that attacker may use to execute JavaScript e.g.,
     * ( is filtered because width:expression(alert(1))
     * & is filtered in order to stop decimal + hex + HTML5 entity encoding
     * < is filtered in case developers are using <style></style> tags instead of style attribute.
     * < is filtered because attacker may close the </style> tag and then execute JavaScript.
     * The function allows simple styles e.g., color:red, height:100px etc.
     * @author Ashar Javed
     * @Link https://twitter.com/soaj1664ashar
     * @demo http://xssplaygroundforfunandlearn.netai.net/final.html
     */
    function styleContextCleaner($input) {
        $bad_chars = array("\"", "'", "``", "(", "\\\\", "<", "&");

        $safe_chars = array("&quot;", "&apos;", "&grave;", "&lpar;", "&bsol;", "&lt;", "&amp;");

        $output = str_replace($bad_chars, $safe_chars, $input);

        return stripslashes($output);
    }

    /**
     * XSS protection function for URL context
     * @usecases
     * <a href="use this function if output reflects here">click</a>
     * <img src="use this function if output reflects here">
     * <iframe src="use this function if output reflects here">
     * @description
     * Only allows URLs that start with http(s) or ftp. e.g.,
     * https://www.google.com
     * Protection against JavaScript, VBScript and Data URI JavaScript code execution etc.
     * @author Ashar Javed
     * @Link https://twitter.com/soaj1664ashar
     * @demo http://xssplaygroundforfunandlearn.netai.net/final.html
     */
    function urlContextCleaner($url) {
        if(preg_match("#^(?:(?:https?|ftp):{1})\/\/[^\"\s\\\\]*.[^\"\s\\\\]*$#iu",(string)$url,$match))
        {
            return $match[0];
        }
        else {
            $noxss='javascript:void(0)';
            return $noxss;
        }
    }