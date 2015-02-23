/*
 *  Copyright (c) 2012-2015 Malhar, Inc.
 *  All Rights Reserved.
 */

package com.datatorrent.lib.appdata.schemas.ads;

import com.datatorrent.lib.appdata.qr.ResultSerializerFactory;
import com.datatorrent.lib.appdata.schemas.TimeSeriesTabularOneTimeQuery;
import com.datatorrent.lib.appdata.schemas.SchemaQuery;
import com.datatorrent.lib.appdata.schemas.SchemaTestUtils;
import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;

/**
 *
 * @author Timothy Farkas: tim@datatorrent.com
 */
public class AdsSchemaResultTest
{
  private static final Logger logger = LoggerFactory.getLogger(AdsSchemaResultTest.class);

  public AdsSchemaResultTest()
  {
  }

  @Test
  public void testSerialization()
  {
    final String id = "js134232342134";
    final String type = "schemaData";
    final String schemaType = "dimensions";
    final String schemaVersion = "1.0";

    final String fromTime = "2015-01-01 00:00:00";
    final String toTime = "2015-12-31 23:59:59";
    final String[] buckets = {"1m", "1h", "1d"};

    final String[] publishers = {"twitter", "facebook", "yahoo", "google"};
    final String[] advertisers = {"starbucks", "safeway", "mcdonalds", "macys"};
    final String[] locations = {"N", "LREC", "SKY"};

    final String time1 = fromTime;
    final String time2 = "2014-03-01 01:00:00";

    final long impressions1 = 7882384;
    final long impressions2 = 7232109;

    final long clicks1 = 13942;
    final long clicks2 = 51789;

    TimeSeriesTabularOneTimeQuery oneTimeQuery = new TimeSeriesTabularOneTimeQuery();
    oneTimeQuery.setId(id);
    oneTimeQuery.setType("oneTimeQuery");

    final String jsonExpected = "{" +
    "\"id\":\"" + id + "\"," +
    "\"type\":\"" + type + "\"," +
    "\"data\":{" +
      "\"schemaType\":\"" + schemaType + "\"," +
      "\"schemaVersion\":\"" + schemaVersion + "\"," +
      "\"timeBuckets\":{" +
      "\"from\":\"" + fromTime + "\"," +
      "\"to\":\"" + toTime + "\"," +
      "\"buckets\":[" + StringUtils.arrayToDelimitedString(SchemaTestUtils.wrap(buckets, "\""), ",") +"]" +
      "}," +
    "\"keys\":[" + "{" +
      "\"name\":\"publisher\"," +
      "\"keyValues\":[" + StringUtils.arrayToDelimitedString(SchemaTestUtils.wrap(publishers, "\""), ",") + "]" +
    "}," +
    "{" +
      "\"name\":\"advertiser\"," +
      "\"keyValues\":[" + StringUtils.arrayToDelimitedString(SchemaTestUtils.wrap(advertisers, "\""), ",") + "]" +
    "}," +
    "{" +
      "\"name\":\"location\"," +
      "\"keyValues\":[" + StringUtils.arrayToDelimitedString(SchemaTestUtils.wrap(locations, "\""), ",") + "]" +
    "}" +
    "]," +
    "\"values\":[" +
      "{\"name\":\"impressions\",\"type\":\"integer\"}," +
      "{\"name\":\"clicks\",\"type\":\"integer\"}," +
      "{\"name\":\"cost\",\"type\":\"float\"}," +
      "{\"name\":\"revenue\",\"type\":\"float\"}" + "]" +
    "}" +
    "}";

    SchemaQuery sq = new SchemaQuery();

    sq.setId(id);
    sq.setType(SchemaQuery.TYPE);

    AdsSchemaResult asr = new AdsSchemaResult(sq);
      /*AdsSchemaData asd = new AdsSchemaData();
      asd.setSchemaType(schemaType);
      asd.setSchemaVersion(schemaVersion);

      TimeRangeBuckets trbs = new TimeRangeBuckets();
      trbs.setFrom(fromTime);
      trbs.setTo(toTime);
      trbs.setBuckets(Arrays.asList(buckets));
      asd.setTimeBuckets(trbs);

      List<KeyMultiValue> kmvs = Lists.newArrayList();
      KeyMultiValue kmv = new KeyMultiValue();
      kmv.setName("publisher");
      kmv.setKeyValues(Arrays.asList(publishers));
      kmvs.add(kmv);

      kmv = new KeyMultiValue();
      kmv.setName("advertiser");
      kmv.setKeyValues(Arrays.asList(advertisers));
      kmvs.add(kmv);

      kmv = new KeyMultiValue();
      kmv.setName("location");
      kmv.setKeyValues(Arrays.asList(locations));
      kmvs.add(kmv);
      asd.setKeys(kmvs);

      List<SchemaValues> schemaValues = Lists.newArrayList();
      SchemaValues svs = new SchemaValues();
      svs.setName("impressions");
      svs.setType("integer");
      schemaValues.add(svs);
      svs = new SchemaValues();
      svs.setName("clicks");
      svs.setType("integer");
      schemaValues.add(svs);
      svs = new SchemaValues();

    sv = new SchemaValues();
    sv.setName(COST);
    sv.setType(COST_TYPE);
    svs.add(sv);

    sv = new SchemaValues();
    sv.setName(REVENUE);
    sv.setType(REVENUE_TYPE);
    svs.add(sv);
      svs.setName("cost");
      svs.setType("float");
      schemaValues.add(svs);
      svs = new SchemaValues();
      svs.setName("cost");
      svs.setType("float");
      schemaValues.add(svs);
      svs = new SchemaValues();
      svs.setName("");

      asd.setValues(schemaValues);

    asr.setData(asd);*/

    ResultSerializerFactory rsf = new ResultSerializerFactory();

    String jsonResult = rsf.serialize(asr);

    logger.debug("Expected: {}", jsonExpected);
    logger.debug("Actual:   {}", jsonResult);

    Assert.assertEquals("Serialized json was not correct", jsonExpected, jsonResult);
  }
}