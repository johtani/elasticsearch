/*
 * Licensed to Elasticsearch under one or more contributor
 * license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright
 * ownership. Elasticsearch licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.elasticsearch.index.analysis;

import org.apache.lucene.analysis.Analyzer;
import org.elasticsearch.Version;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.set.Sets;
import org.elasticsearch.env.Environment;
import org.elasticsearch.index.AbstractIndexComponent;
import org.elasticsearch.index.IndexSettings;
import org.elasticsearch.index.mapper.TextFieldMapper;
import org.elasticsearch.indices.analysis.AnalysisModule;

import java.io.Closeable;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static java.util.Collections.unmodifiableMap;

/**
 *
 */
public class AnalysisService extends AbstractIndexComponent implements Closeable {

    private final Map<String, NamedAnalyzer> analyzers;

    private final NamedAnalyzer defaultIndexAnalyzer;
    private final NamedAnalyzer defaultSearchAnalyzer;
    private final NamedAnalyzer defaultSearchQuoteAnalyzer;

    private final AnalysisRegistry analysisRegistry;
    private final Environment environment;

    public AnalysisService(IndexSettings indexSettings,
                           AnalysisRegistry analysisRegistry,
                           Environment environment,
                           Map<String, AnalyzerProvider<?>> analyzerProviders) {
        super(indexSettings);
        this.analysisRegistry = analysisRegistry;
        this.environment = environment;
        analyzerProviders = new HashMap<>(analyzerProviders);

        Map<String, NamedAnalyzer> analyzerAliases = new HashMap<>();
        Map<String, NamedAnalyzer> analyzers = new HashMap<>();
        for (Map.Entry<String, AnalyzerProvider<?>> entry : analyzerProviders.entrySet()) {
            processAnalyzerFactory(entry.getKey(), entry.getValue(), analyzerAliases, analyzers);
        }
        for (Map.Entry<String, NamedAnalyzer> entry : analyzerAliases.entrySet()) {
            String key = entry.getKey();
            if (analyzers.containsKey(key) &&
                ("default".equals(key) || "default_search".equals(key) || "default_search_quoted".equals(key)) == false) {
                throw new IllegalStateException("already registered analyzer with name: " + key);
            } else {
                NamedAnalyzer configured = entry.getValue();
                analyzers.put(key, configured);
            }
        }

        if (!analyzers.containsKey("default")) {
            processAnalyzerFactory("default", new StandardAnalyzerProvider(indexSettings, null, "default", Settings.Builder.EMPTY_SETTINGS),
                analyzerAliases, analyzers);
        }
        if (!analyzers.containsKey("default_search")) {
            analyzers.put("default_search", analyzers.get("default"));
        }
        if (!analyzers.containsKey("default_search_quoted")) {
            analyzers.put("default_search_quoted", analyzers.get("default_search"));
        }


        NamedAnalyzer defaultAnalyzer = analyzers.get("default");
        if (defaultAnalyzer == null) {
            throw new IllegalArgumentException("no default analyzer configured");
        }
        if (analyzers.containsKey("default_index")) {
            final Version createdVersion = indexSettings.getIndexVersionCreated();
            if (createdVersion.onOrAfter(Version.V_5_0_0_alpha1)) {
                throw new IllegalArgumentException("setting [index.analysis.analyzer.default_index] is not supported anymore, use [index.analysis.analyzer.default] instead for index [" + index().getName() + "]");
            } else {
                deprecationLogger.deprecated("setting [index.analysis.analyzer.default_index] is deprecated, use [index.analysis.analyzer.default] instead for index [{}]", index().getName());
            }
        }
        defaultIndexAnalyzer = analyzers.containsKey("default_index") ? analyzers.get("default_index") : defaultAnalyzer;
        defaultSearchAnalyzer = analyzers.containsKey("default_search") ? analyzers.get("default_search") : defaultAnalyzer;
        defaultSearchQuoteAnalyzer = analyzers.containsKey("default_search_quote") ? analyzers.get("default_search_quote") : defaultSearchAnalyzer;

        for (Map.Entry<String, NamedAnalyzer> analyzer : analyzers.entrySet()) {
            if (analyzer.getKey().startsWith("_")) {
                throw new IllegalArgumentException("analyzer name must not start with '_'. got \"" + analyzer.getKey() + "\"");
            }
        }
        this.analyzers = unmodifiableMap(analyzers);
    }

    private void processAnalyzerFactory(String name, AnalyzerProvider<?> analyzerFactory, Map<String, NamedAnalyzer> analyzerAliases, Map<String, NamedAnalyzer> analyzers) {
        /*
         * Lucene defaults positionIncrementGap to 0 in all analyzers but
         * Elasticsearch defaults them to 0 only before version 2.0
         * and 100 afterwards so we override the positionIncrementGap if it
         * doesn't match here.
         */
        int overridePositionIncrementGap = TextFieldMapper.Defaults.POSITION_INCREMENT_GAP;
        if (analyzerFactory instanceof CustomAnalyzerProvider) {
            ((CustomAnalyzerProvider) analyzerFactory).build(this);
            /*
             * Custom analyzers already default to the correct, version
             * dependent positionIncrementGap and the user is be able to
             * configure the positionIncrementGap directly on the analyzer so
             * we disable overriding the positionIncrementGap to preserve the
             * user's setting.
             */
            overridePositionIncrementGap = Integer.MIN_VALUE;
        }
        Analyzer analyzerF = analyzerFactory.get();
        if (analyzerF == null) {
            throw new IllegalArgumentException("analyzer [" + analyzerFactory.name() + "] created null analyzer");
        }
        NamedAnalyzer analyzer;
        if (analyzerF instanceof NamedAnalyzer) {
            // if we got a named analyzer back, use it...
            analyzer = (NamedAnalyzer) analyzerF;
            if (overridePositionIncrementGap >= 0 && analyzer.getPositionIncrementGap(analyzer.name()) != overridePositionIncrementGap) {
                // unless the positionIncrementGap needs to be overridden
                analyzer = new NamedAnalyzer(analyzer, overridePositionIncrementGap);
            }
        } else {
            analyzer = new NamedAnalyzer(name, analyzerFactory.scope(), analyzerF, overridePositionIncrementGap);
        }
        if (analyzers.containsKey(name)) {
            throw new IllegalStateException("already registered analyzer with name: " + name);
        }
        analyzers.put(name, analyzer);
        // TODO: remove alias support completely when we no longer support pre 5.0 indices
        final String analyzerAliasKey = "index.analysis.analyzer." + analyzerFactory.name() + ".alias";
        if (indexSettings.getSettings().get(analyzerAliasKey) != null) {
            if (indexSettings.getIndexVersionCreated().onOrAfter(Version.V_5_0_0_alpha6)) {
                // do not allow alias creation if the index was created on or after v5.0 alpha6
                throw new IllegalArgumentException("setting [" + analyzerAliasKey + "] is not supported");
            }

            // the setting is now removed but we only support it for loading indices created before v5.0
            deprecationLogger.deprecated("setting [{}] is only allowed on index [{}] because it was created before 5.x; " +
                                         "analyzer aliases can no longer be created on new indices.", analyzerAliasKey, index().getName());
            Set<String> aliases = Sets.newHashSet(indexSettings.getSettings().getAsArray(analyzerAliasKey));
            for (String alias : aliases) {
                if (analyzerAliases.putIfAbsent(alias, analyzer) != null) {
                    throw new IllegalStateException("alias [" + alias + "] is already used by [" + analyzerAliases.get(alias).name() + "]");
                }
            }
        }
    }

    @Override
    public void close() {
        for (NamedAnalyzer analyzer : analyzers.values()) {
            if (analyzer.scope() == AnalyzerScope.INDEX) {
                try {
                    analyzer.close();
                } catch (NullPointerException e) {
                    // because analyzers are aliased, they might be closed several times
                    // an NPE is thrown in this case, so ignore....
                    // TODO: Analyzer's can no longer have aliases in indices created in 5.x and beyond,
                    // so we only allow the aliases for analyzers on indices created pre 5.x for backwards
                    // compatibility.  Once pre 5.0 indices are no longer supported, this check should be removed.
                } catch (Exception e) {
                    logger.debug("failed to close analyzer {}", analyzer);
                }
            }
        }
    }

    public NamedAnalyzer analyzer(String name) {
        return analyzers.get(name);
    }

    public NamedAnalyzer defaultIndexAnalyzer() {
        return defaultIndexAnalyzer;
    }

    public NamedAnalyzer defaultSearchAnalyzer() {
        return defaultSearchAnalyzer;
    }

    public NamedAnalyzer defaultSearchQuoteAnalyzer() {
        return defaultSearchQuoteAnalyzer;
    }

    public TokenizerFactory tokenizer(String tokenizerName) {
        AnalysisModule.AnalysisProvider<TokenizerFactory> tokenizerFactoryFactory =
            this.analysisRegistry.getTokenizerProvider(tokenizerName, this.indexSettings);
        if (tokenizerFactoryFactory == null) {
            throw new IllegalArgumentException("failed to find tokenizer under [" + tokenizerName + "]");
        }
        TokenizerFactory tokenizer;
        try {
            tokenizer =
                tokenizerFactoryFactory.get(this.indexSettings, this.environment, tokenizerName,
                    AnalysisRegistry.getSettingsFromIndexSettings(this.indexSettings,
                        AnalysisRegistry.INDEX_ANALYSIS_TOKENIZER + "." + tokenizerName));
        } catch (IOException ioe) {
            throw new IllegalArgumentException("failed to find tokenizer under name [" + tokenizerName + "]", ioe);
        }
        return tokenizer;
    }

    public TokenFilterFactory tokenFilter(String tokenFilterName) {
        AnalysisModule.AnalysisProvider<TokenFilterFactory> tokenFilterfactoryFactory =
            this.analysisRegistry.getTokenFilterProvider(tokenFilterName, this.indexSettings);
        if (tokenFilterfactoryFactory == null) {
            throw new IllegalArgumentException("failed to find token filter under [" + tokenFilterName + "]");
        }
        TokenFilterFactory tokenFilter;
        try {
            tokenFilter =
                tokenFilterfactoryFactory.get(this.indexSettings, this.environment, tokenFilterName,
                    AnalysisRegistry.getSettingsFromIndexSettings(this.indexSettings,
                        AnalysisRegistry.INDEX_ANALYSIS_FILTER + "." + tokenFilterName));
        } catch (IOException ioe) {
            throw new IllegalArgumentException("failed to find token filter under name [" + tokenFilterName + "]", ioe);
        }
        return tokenFilter;

    }

    public CharFilterFactory charFilter(String charFilterName) {
        AnalysisModule.AnalysisProvider<CharFilterFactory> charFilterFactoryFactory =
            this.analysisRegistry.getCharFilterProvider(charFilterName, this.indexSettings);
        if (charFilterFactoryFactory == null) {
            throw new IllegalArgumentException("failed to find char_filter under [" + charFilterName + "]");
        }
        CharFilterFactory charFilter;
        try {
            charFilter =
                charFilterFactoryFactory.get(this.indexSettings, this.environment, charFilterName,
                    AnalysisRegistry.getSettingsFromIndexSettings(this.indexSettings,
                        AnalysisRegistry.INDEX_ANALYSIS_CHAR_FILTER + "." + charFilterName));
        } catch (IOException ioe) {
            throw new IllegalArgumentException("failed to find char_filter under name [" + charFilterName + "]", ioe);
        }
        return charFilter;

    }
}
