/**
 * Copyright (c) 2012, Warwick Hunter. All rights reserved.
 * Copyright 2012, Sean Flanigan. All rights reserved.
 * <p>
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * <p>
 * 1. Redistributions of source code must retain the above copyright notice, this list
 * of conditions and the following disclaimer.
 * <p>
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 * list of conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution.
 * <p>
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package org.computer.whunter.rpm.parser;

import com.google.common.collect.LinkedListMultimap;
import com.google.common.collect.Multimap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * This is a parser of an RPM Spec file. It extracts a number of properties from an RPM spec file
 * and presents them as properties. Some properties can refer to the values of other properties with
 * a syntax of %{fieldName}. The references are expanded in the properties where possible.
 *
 * @author Warwick Hunter (w.hunter@computer.org)
 * {@code @date} 2012-02-22
 * @see <a href="https://github.com/warwickhunter/rpm-spec-parser">https://github.com/warwickhunter/rpm-spec-parser</a>
 */
public class RpmSpecParser {

    private static final Logger logger = LoggerFactory.getLogger(RpmSpecParser.class);

    private static final String[] COMMON_FIELDS = {"name", "version", "release", "buildrequires", "requires",
            "summary", "license", "vendor", "packager", "provides",
            "url", "source[0-9]+", "group", "buildRoot", "buildArch",
            "autoreqprov", "prefix", "Patch[0-9]+"};

    private static final String[] MACRO_FIELDS = {"package"};

    // FIXME 非标处理，后续优化
    private static final Map<Pattern, String> BUILD_IN_MACRO_VALUE_MAPPING = new HashMap<>() {
        {
            put(Pattern.compile("%\\{python3_pkgversion\\}"), "3");
            put(Pattern.compile("%\\{python3_other_pkgversion\\}"), "3");
            put(Pattern.compile("%\\{vendor\\}"), "openEuler");
            put(Pattern.compile("%\\{package64kb\\}"), "");
        }
    };

    private static final String[] INNER_MACRO_PATTERNS = {"^%define\\s.*", "^%global\\s.*"};

    private final Map<Pattern, String> m_fieldPatterns = new HashMap<>();
    private final Map<Pattern, String> m_fieldReferenceMatcherPatterns = new HashMap<>();
    private final Map<String, Pattern> m_fieldReferenceReplacePatterns = new HashMap<>();
    private final Map<Pattern, String> m_placeholderReferenceMatcherPatterns = new HashMap<>();
    private final Map<String, Pattern> m_placeholderReferenceReplacePatterns = new HashMap<>();

    private final String specFileContent;

    /**
     * Create a parser that will parse an RPM spec file.
     *
     * @param specFilePath the patch of the spec file to parse.
     * @return a parser ready to parse the file.
     */
    public static RpmSpecParser createParserByFile(String specFilePath) throws IOException {
        return new RpmSpecParser(Files.readString(Path.of(specFilePath), StandardCharsets.UTF_8));
    }

    public static RpmSpecParser createParserByContent(String specFileContent) {
        return new RpmSpecParser(specFileContent);
    }

    /**
     * Private constructor
     */
    private RpmSpecParser(String specFileContent) {
        this.specFileContent = specFileContent;

        initFields(COMMON_FIELDS, Boolean.FALSE);
        initFields(MACRO_FIELDS, Boolean.TRUE);
    }

    private void initFields(String[] fields, boolean isMacro) {
        // Take the list of strings and turn them into case-insensitive pattern matchers
        Map<Pattern, String> fieldRegexes = new HashMap<>();
        Map<Pattern, String> macroMatchRegexes = new HashMap<>();
        Map<String, Pattern> macroReplaceRegexes = new HashMap<>();
        for (String field : fields) {
            StringBuilder fieldRegex = new StringBuilder("^");
            StringBuilder macroMatchRegex = new StringBuilder(".*%\\{");
            StringBuilder macroReplaceRegex = new StringBuilder("%\\{");
            fieldRegex.append("(");
            if (isMacro) {
                fieldRegex.append("%");
            }
            for (int i = 0; i < field.length(); ++i) {
                char ch = field.charAt(i);
                if (Character.isLetter(ch)) {
                    String regex = String.format("[%c%c]", Character.toLowerCase(ch), Character.toUpperCase(ch));
                    fieldRegex.append(regex);
                    macroMatchRegex.append(regex);
                    macroReplaceRegex.append(regex);
                } else {
                    fieldRegex.append(ch);
                    macroMatchRegex.append(ch);
                    macroReplaceRegex.append(ch);
                }
            }

            if (isMacro) {
                fieldRegex.append(")(.*)");
            } else {
                fieldRegex.append(")\\s*:(.*)");
            }

            macroMatchRegex.append("\\}.*");
            macroReplaceRegex.append("\\}");
            fieldRegexes.put(Pattern.compile(fieldRegex.toString()), field);
            macroMatchRegexes.put(Pattern.compile(macroMatchRegex.toString()), field);
            macroReplaceRegexes.put(macroMatchRegex.toString(), Pattern.compile(macroReplaceRegex.toString()));
        }
        m_fieldPatterns.putAll(fieldRegexes);
        m_fieldReferenceMatcherPatterns.putAll(macroMatchRegexes);
        m_fieldReferenceReplacePatterns.putAll(macroReplaceRegexes);
    }

    /**
     * Parse the RPM spec file. Each of the supported fields is placed into the {@link Properties} returned.
     *
     * @return the {@link Properties} of the spec file.
     * @throws FileNotFoundException if the path of the spec file could not be opened for reading.
     */
    public Multimap<String, String> parse() throws FileNotFoundException {
        Multimap<String, String> properties = LinkedListMultimap.create();
        Scanner scanner = new Scanner(this.specFileContent);
        while (scanner.hasNextLine()) {
            String line = scanner.nextLine().trim();
            if (line.startsWith("#")) {
                // Discard comments
                continue;
            }

            // Examine the line to see if it's a macro definition
            for (String innerMacroPatterns : INNER_MACRO_PATTERNS) {
                if (line.matches(innerMacroPatterns)) {
                    String[] words = line.split("\\s+");
                    if (words.length > 2) {
                        StringBuilder value = new StringBuilder();
                        for (int i = 2; i < words.length; ++i) {
                            if (i != 2) {
                                value.append(" ");
                            }
                            value.append(words[i]);
                        }

                        if (properties.containsKey(words[1])) {
                            logger.debug("macro field:{} is duplicate", words[1]);
                            continue;
                        }
                        properties.put(words[1], value.toString().trim());
                        // Add a matcher pattern for it so that any references to it can be expanded
                        StringBuilder macroMatchRegex = new StringBuilder(".*%\\{");
                        StringBuilder macroReplaceRegex = new StringBuilder("%\\{");
                        for (int i = 0; i < words[1].length(); ++i) {
                            char ch = words[1].charAt(i);
                            if (Character.isLetter(ch)) {
                                String regex = String.format("[%c%c]", Character.toLowerCase(ch), Character.toUpperCase(ch));
                                macroMatchRegex.append(regex);
                                macroReplaceRegex.append(regex);
                            } else {
                                macroMatchRegex.append(ch);
                                macroReplaceRegex.append(ch);
                            }
                        }
                        macroMatchRegex.append("\\}.*");
                        macroReplaceRegex.append("\\}");
                        m_placeholderReferenceMatcherPatterns.put(Pattern.compile(macroMatchRegex.toString()), words[1]);
                        m_placeholderReferenceReplacePatterns.put(macroMatchRegex.toString(), Pattern.compile(macroReplaceRegex.toString()));
                    }
                }
            }
            // Examine the line to see if it's a field
            for (Map.Entry<Pattern, String> entry : m_fieldPatterns.entrySet()) {
                Matcher matcher = entry.getKey().matcher(line);
                if (matcher.matches() && matcher.groupCount() > 1) {
                    properties.put(matcher.group(1).toLowerCase(), matcher.group(2).trim());
                }
            }
        }
        expandReferences(properties);
        return properties;
    }

    /**
     * The values of fields and macros can themselves contain the values of other directives. Search through the
     * properties and replace these values if they are present.
     *
     * @param properties the properties to modify by expanding any values
     */
    private void expandReferences(Multimap<String, String> properties) {

        Map<Pattern, String> matcherPatterns = new HashMap<>();
        matcherPatterns.putAll(m_fieldReferenceMatcherPatterns);
        matcherPatterns.putAll(m_placeholderReferenceMatcherPatterns);

        Map<String, Pattern> replacePatterns = new HashMap<>();
        replacePatterns.putAll(m_fieldReferenceReplacePatterns);
        replacePatterns.putAll(m_placeholderReferenceReplacePatterns);

        Multimap<String, String> newProperties = LinkedListMultimap.create();
        for (Entry<String, String> property : properties.entries()) {
            String newValue = expandReferences(property.getValue(), properties, newProperties, matcherPatterns, replacePatterns);
            newProperties.put(property.getKey(), newValue);
        }
        properties.clear();
        properties.putAll(newProperties);
    }

    /**
     * The values of fields and macros can themselves contain the values of other directives. Search through the
     * property value and replace these values if they are present.
     *
     * @param propertyValue   the value to search for any replacements
     * @param oldProperties   the properties to use to expand any values
     * @param newProperties   the properties to use to expand any values
     * @param matcherPatterns patterns to find references to fields or macros
     * @param replacePatterns patters to replace references to fields or macros with the values
     */
    private String expandReferences(String propertyValue, Multimap<String, String> oldProperties, Multimap<String, String> newProperties,
                                    Map<Pattern, String> matcherPatterns,
                                    Map<String, Pattern> replacePatterns) {
        // optional macro
        String newValue = propertyValue.replaceAll("\\%\\{\\?", "%{");

        // replace build-in macros
        for (Map.Entry<Pattern, String> macro : BUILD_IN_MACRO_VALUE_MAPPING.entrySet()) {
            newValue = newValue.replaceAll(macro.getKey().toString(), macro.getValue());
        }
        for (Map.Entry<Pattern, String> macro : matcherPatterns.entrySet()) {
            Matcher matcher = macro.getKey().matcher(newValue);
            if (matcher.matches()) {
                Pattern replacePattern = replacePatterns.get(macro.getKey().toString());
                String replaceValue = getProperty(oldProperties, newProperties, macro.getValue());
                if (replaceValue == null) {
                    Matcher findMatcher = Pattern.compile(macro.getValue()).matcher(newValue.toLowerCase());
                    if (findMatcher.find()) {
                        replaceValue = getProperty(oldProperties, newProperties, findMatcher.group(0));
                    }
                }
                if (replaceValue == null) {
                    logger.debug("replacePattern:{} cant find replaceVale", replacePattern.toString());
                    continue;
                } else if (replaceValue.contains("%")) {
                    logger.debug("replaceVale:{} contains %, skip", replacePattern.toString());
                    continue;
                } else if (replaceValue.contains("$")) {
                    logger.debug("replaceVale:{} contains $, skip", replacePattern.toString());
                    continue;
                } else if (replaceValue.endsWith("\\")) {
                    logger.debug("replaceVale:{} end with \\, skip", replacePattern.toString());
                    continue;
                }
                newValue = newValue.replaceAll(replacePattern.toString(), replaceValue);
            }
        }
        if (newValue.equalsIgnoreCase(propertyValue.replaceAll("\\%\\{\\?", "%{"))) {
            newValue = propertyValue.replaceAll("\\%\\{\\?.*\\}", "");
        }
        return newValue;
    }

    String getProperty(Multimap<String, String> oldProperties, Multimap<String, String> newProperties, String key) {
        Collection<String> collection = newProperties.containsKey(key) ? newProperties.get(key) : oldProperties.get(key);
        if (collection.isEmpty())
            return null;

        return collection.iterator().next();
    }

    /**
     * use last one when multi value
     */
    public Properties toProperties(Multimap<String, String> multimap) {
        Properties props = new Properties();
        for (Map.Entry<String, String> entry : multimap.entries()) {
            props.setProperty(entry.getKey(), entry.getValue());
        }
        return props;
    }
}
