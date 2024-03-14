/*
 * Java Authorization Info jai_01
 * Copyright (C) 2021  Suomen Kanuuna Oy
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://github.com/teragrep/teragrep/blob/main/LICENSE>.
 *
 *
 * Additional permission under GNU Affero General Public License version 3
 * section 7
 *
 * If you modify this Program, or any covered work, by linking or combining it
 * with other code, such other code is not for that reason alone subject to any
 * of the requirements of the GNU Affero GPL version 3 as long as this Program
 * is the same Program as licensed from Suomen Kanuuna Oy without any additional
 * modifications.
 *
 * Supplemented terms under GNU Affero General Public License version 3
 * section 7
 *
 * Origin of the software must be attributed to Suomen Kanuuna Oy. Any modified
 * versions must be marked as "Modified version of" The Program.
 *
 * Names of the licensors and authors may not be used for publicity purposes.
 *
 * No rights are granted for use of trade names, trademarks, or service marks
 * which are in The Program if any.
 *
 * Licensee must indemnify licensors and authors for any liability that these
 * contractual assumptions impose on licensors and authors.
 *
 * To the extent this program is licensed as part of the Commercial versions of
 * Teragrep, the applicable Commercial License may apply to this file if you as
 * a licensee so wish it.
 */

package com.teragrep.jai_01;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.gson.Gson;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.PathMatcher;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.HashSet;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

public class ReloadingAuthorizationInfoProcessor implements IAuthorizationInfoProcessor {
    private static final Logger logger = LoggerFactory.getLogger(
            ReloadingAuthorizationInfoProcessor.class);

    // uses following model, where Key is location and value is the parsed
    // LoadingCache<String, HashMap<String, HashSet<String>>> loadingCache;

    private final LoadingCache<String, HashMap<String, HashSet<String>>> loadingCache;

    private final String authorizeJSONlocation;

    private final Gson gson = new Gson();

    public ReloadingAuthorizationInfoProcessor(String authorizeJSONlocation, long seconds) {

        this.authorizeJSONlocation = authorizeJSONlocation;

        CacheLoader<String, HashMap<String, HashSet<String>>> cacheLoader =
                new CacheLoader<String, HashMap<String, HashSet<String>>>() {
                    @Override
                    public HashMap<String, HashSet<String>> load(String authorizeJSONlocation) {
                        final HashMap<String, HashSet<String>> indexToGroups = new HashMap<>();

                        try (BufferedReader bufferedReader = new BufferedReader(
                                new FileReader(authorizeJSONlocation))) {

                            // ++ same as in AuthorizationInfoProcessor
                            AuthorizationInfo[] obj = gson.fromJson(bufferedReader, AuthorizationInfo[].class);

                            for (AuthorizationInfo authorizationInfo : obj) {

                                if ("".equals(authorizationInfo.getGroup()))
                                    continue; // not permitting empty group name

                                for (String index : authorizationInfo.getAllowedIndexes()) {
                                    if("".equals(index))
                                        continue; // not permitting empty index name

                                    if (!indexToGroups.containsKey(index)) {
                                        indexToGroups.put(index, new HashSet<>());
                                    }

                                    indexToGroups.get(index).add(authorizationInfo.getGroup());
                                }
                            }
                            // -- same as in AuthorizationInfoProcessor
                        } catch (IOException e) {
                            logger.error(e.toString());
                        }
                        return indexToGroups;
                    }
                };

        loadingCache = CacheBuilder.newBuilder()
                .maximumSize(1)
                .refreshAfterWrite(seconds, TimeUnit.SECONDS)
                .build(cacheLoader);
    }

    @Override
    public HashSet<String> getGroupsForIndex(String index) {
        HashMap<String, HashSet<String>> indexToGroups = new HashMap<>();

        try {
            indexToGroups = loadingCache.get(authorizeJSONlocation);
        }
        catch (ExecutionException e) {
            logger.error(e.toString());
        }

        // ++ same as in AuthorizationInfoProcessor
        final HashSet<String> allowedGroups = new HashSet<>();
        // keys of the indexToGroups are glob patterns, therefore indexMatcher
        for (String indexMatcher: indexToGroups.keySet()) {
            final String glob = "glob:" + indexMatcher;
            final PathMatcher matcher = FileSystems.getDefault().getPathMatcher(glob);
            if (matcher.matches(Paths.get(index))) {
                allowedGroups.addAll(indexToGroups.get(indexMatcher));
            }
        }
        return allowedGroups;
        // -- same as in AuthorizationInfoProcessor
    }

    @Override
    public HashSet<String> getGroupSetForIndexes(HashSet<String> indexes) {
        // ++ same as in AuthorizationInfoProcessor
        final HashSet<String> groupSet = new HashSet<>();

        for (final String index: indexes) {
            groupSet.addAll(getGroupsForIndex(index));
        }
        return groupSet;
        // -- same as in AuthorizationInfoProcessor
    }
}
