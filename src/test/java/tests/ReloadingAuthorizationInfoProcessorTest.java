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

package tests;

import com.teragrep.jai_01.IAuthorizationInfoProcessor;
import com.teragrep.jai_01.ReloadingAuthorizationInfoProcessor;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.BufferedWriter;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

public class ReloadingAuthorizationInfoProcessorTest {

    @Test()
    public void readTest() throws FileNotFoundException {
        IAuthorizationInfoProcessor authorizationInfoProcessor = new ReloadingAuthorizationInfoProcessor("src/test/resources/authorize.json", 300);

        final Set<String> expectedSet = new HashSet<>();
        expectedSet.add("all-access");
        expectedSet.add("example");
        expectedSet.add("specific");

        Assertions.assertEquals(expectedSet, authorizationInfoProcessor.getGroupsForIndex("example-two"));
    }

    @Test()
    public void reloadTest() throws IOException, InterruptedException {
        final String originalAuthorization = "[{\"group\":\"mygrp\",\"allowedIndexes\":[\"my-test\",\"my-info\"]}]";
        final String changedAuthorization = "[{\"group\":\"differentgrp\",\"allowedIndexes\":[\"my-test\",\"my-info\"]}]";

        final String testFile = "target/authorize.reload.json";

        try(BufferedWriter writer = new BufferedWriter(new FileWriter(testFile))) {
            writer.write(originalAuthorization);
        }

        IAuthorizationInfoProcessor authorizationInfoProcessor = new ReloadingAuthorizationInfoProcessor(testFile, 1);
        final Set<String> originalExpectedSet = new HashSet<>();
        originalExpectedSet.add("mygrp");
        Assertions.assertEquals(originalExpectedSet, authorizationInfoProcessor.getGroupsForIndex("my-test"));

        try(BufferedWriter writer = new BufferedWriter(new FileWriter(testFile))) {
            writer.write(changedAuthorization);
        }

        Thread.sleep(2000);

        final Set<String> changedExpectedSet = new HashSet<>();
        changedExpectedSet.add("differentgrp");

        Assertions.assertEquals(changedExpectedSet, authorizationInfoProcessor.getGroupsForIndex("my-test"));
    }
}
