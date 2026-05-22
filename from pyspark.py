from pyspark.sql import SparkSession
from pyspark.sql.functions import col, trim

spark = SparkSession.builder.appName("CreditCardChurn_Preprocess").getOrCreate()

# INPUT CSV (    )
input_csv = r"C:\Users\Lenovo\Desktop\archive\credit_card_churn.csv"

# Read data
df = (spark.read
      .option("header", True)
      .option("inferSchema", True)
      .csv(input_csv))

# Simple cleaning (Spark is used )
for c, t in df.dtypes:
    if t == "string":
        df = df.withColumn(c, trim(col(c)))

# Drop rows without target
df = df.na.drop(subset=["Churn"])

# Fill remaining nulls (basic)
df = df.na.fill("Unknown")

# OUTPUT directory
output_dir = r"C:\Users\Lenovo\Desktop\orang\Credit-card-churn-predictions-using-orange--main\Credit-card-churn-predictions-using-orange--main\spark_output"

# Write CSV (single part)
(df.coalesce(1)
 .write
 .mode("overwrite")
 .option("header", True)
 .csv(output_dir))

spark.stop()
