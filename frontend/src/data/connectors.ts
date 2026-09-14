export type ConnectorCategory =
  | 'database'
  | 'dashboard'
  | 'messaging'
  | 'pipeline'
  | 'ml_model'
  | 'storage'
  | 'search'
  | 'drive'
  | 'metadata'
  | 'api';

export interface Connector {
  type: string;
  display_name: string;
  category: ConnectorCategory;
}

export const CATEGORY_LABELS: Record<ConnectorCategory, string> = {
  database:  'Database',
  dashboard: 'Dashboard',
  messaging: 'Messaging',
  pipeline:  'Pipeline',
  ml_model:  'ML Model',
  storage:   'Storage',
  search:    'Search',
  drive:     'Drive',
  metadata:  'Metadata',
  api:       'API',
};

export const CATEGORY_COLORS: Record<ConnectorCategory, string> = {
  database:  'bg-blue-100 text-blue-800',
  dashboard: 'bg-purple-100 text-purple-800',
  messaging: 'bg-orange-100 text-orange-800',
  pipeline:  'bg-green-100 text-green-800',
  ml_model:  'bg-pink-100 text-pink-800',
  storage:   'bg-yellow-100 text-yellow-800',
  search:    'bg-cyan-100 text-cyan-800',
  drive:     'bg-gray-100 text-gray-800',
  metadata:  'bg-indigo-100 text-indigo-800',
  api:       'bg-teal-100 text-teal-800',
};

// Ordered category display
export const CATEGORY_ORDER: ConnectorCategory[] = [
  'database', 'dashboard', 'messaging', 'pipeline',
  'ml_model', 'storage', 'search', 'drive', 'metadata', 'api',
];

export const CONNECTORS: Connector[] = [
  // Database
  { type: 'adls_datalake',  display_name: 'ADLS Datalake',   category: 'database' },
  { type: 'athena',         display_name: 'Athena',           category: 'database' },
  { type: 'azuresql',       display_name: 'Azure SQL',        category: 'database' },
  { type: 'bigquery',       display_name: 'BigQuery',         category: 'database' },
  { type: 'bigtable',       display_name: 'BigTable',         category: 'database' },
  { type: 'cassandra',      display_name: 'Cassandra',        category: 'database' },
  { type: 'clickhouse',     display_name: 'ClickHouse',       category: 'database' },
  { type: 'cockroach',      display_name: 'CockroachDB',      category: 'database' },
  { type: 'couchbase',      display_name: 'Couchbase',        category: 'database' },
  { type: 'databricks',     display_name: 'Databricks',       category: 'database' },
  { type: 'db2',            display_name: 'DB2',              category: 'database' },
  { type: 'dbt',            display_name: 'dbt',              category: 'database' },
  { type: 'delta_lake',     display_name: 'Delta Lake',       category: 'database' },
  { type: 'doris',          display_name: 'Doris',            category: 'database' },
  { type: 'druid',          display_name: 'Druid',            category: 'database' },
  { type: 'dynamodb',       display_name: 'DynamoDB',         category: 'database' },
  { type: 'exasol',         display_name: 'Exasol',           category: 'database' },
  { type: 'gcs_datalake',   display_name: 'GCS Datalake',     category: 'database' },
  { type: 'glue',           display_name: 'Glue',             category: 'database' },
  { type: 'greenplum',      display_name: 'Greenplum',        category: 'database' },
  { type: 'hive',           display_name: 'Hive',             category: 'database' },
  { type: 'impala',         display_name: 'Impala',           category: 'database' },
  { type: 'mariadb',        display_name: 'MariaDB',          category: 'database' },
  { type: 'mongodb',        display_name: 'MongoDB',          category: 'database' },
  { type: 'mssql',          display_name: 'MSSQL',            category: 'database' },
  { type: 'mysql',          display_name: 'MySQL',            category: 'database' },
  { type: 'oracle',         display_name: 'Oracle',           category: 'database' },
  { type: 'oracle_erp',     display_name: 'Oracle ERP',       category: 'database' },
  { type: 'pinotdb',        display_name: 'PinotDB',          category: 'database' },
  { type: 'postgres',       display_name: 'PostgreSQL',       category: 'database' },
  { type: 'presto',         display_name: 'Presto',           category: 'database' },
  { type: 'redshift',       display_name: 'Redshift',         category: 'database' },
  { type: 's3_datalake',    display_name: 'S3 Datalake',      category: 'database' },
  { type: 'salesforce',     display_name: 'Salesforce',       category: 'database' },
  { type: 'sap_erp',        display_name: 'SAP ERP',          category: 'database' },
  { type: 'sap_hana',       display_name: 'SAP HANA',         category: 'database' },
  { type: 'singlestore',    display_name: 'SingleStore',      category: 'database' },
  { type: 'snowflake',      display_name: 'Snowflake',        category: 'database' },
  { type: 'sqlite',         display_name: 'SQLite',           category: 'database' },
  { type: 'starrocks',      display_name: 'StarRocks',        category: 'database' },
  { type: 'teradata',       display_name: 'Teradata',         category: 'database' },
  { type: 'timescaledb',    display_name: 'TimescaleDB',      category: 'database' },
  { type: 'trino',          display_name: 'Trino',            category: 'database' },
  { type: 'unity_catalog',  display_name: 'Unity Catalog',    category: 'database' },
  { type: 'vertica',        display_name: 'Vertica',          category: 'database' },

  // Dashboard
  { type: 'grafana',        display_name: 'Grafana',          category: 'dashboard' },
  { type: 'hex',            display_name: 'Hex',              category: 'dashboard' },
  { type: 'lightdash',      display_name: 'Lightdash',        category: 'dashboard' },
  { type: 'looker',         display_name: 'Looker',           category: 'dashboard' },
  { type: 'metabase',       display_name: 'Metabase',         category: 'dashboard' },
  { type: 'microstrategy',  display_name: 'MicroStrategy',    category: 'dashboard' },
  { type: 'mode',           display_name: 'Mode',             category: 'dashboard' },
  { type: 'powerbi',        display_name: 'PowerBI',          category: 'dashboard' },
  { type: 'qlik_cloud',     display_name: 'Qlik Cloud',       category: 'dashboard' },
  { type: 'qlik_sense',     display_name: 'Qlik Sense',       category: 'dashboard' },
  { type: 'quicksight',     display_name: 'QuickSight',       category: 'dashboard' },
  { type: 'redash',         display_name: 'Redash',           category: 'dashboard' },
  { type: 'sigma',          display_name: 'Sigma',            category: 'dashboard' },
  { type: 'superset',       display_name: 'Superset',         category: 'dashboard' },
  { type: 'tableau',        display_name: 'Tableau',          category: 'dashboard' },
  { type: 'domo_dashboard', display_name: 'Domo',             category: 'dashboard' },

  // Messaging
  { type: 'kafka',          display_name: 'Kafka',            category: 'messaging' },
  { type: 'kinesis',        display_name: 'Kinesis',          category: 'messaging' },
  { type: 'redpanda',       display_name: 'Redpanda',         category: 'messaging' },

  // Pipeline
  { type: 'airbyte',        display_name: 'Airbyte',          category: 'pipeline' },
  { type: 'airflow',        display_name: 'Airflow',          category: 'pipeline' },
  { type: 'dagster',        display_name: 'Dagster',          category: 'pipeline' },
  { type: 'dbt_cloud',      display_name: 'dbt Cloud',        category: 'pipeline' },
  { type: 'domo_pipeline',  display_name: 'Domo Pipeline',    category: 'pipeline' },
  { type: 'fivetran',       display_name: 'Fivetran',         category: 'pipeline' },
  { type: 'flink',          display_name: 'Flink',            category: 'pipeline' },
  { type: 'glue_pipeline',  display_name: 'Glue Pipeline',    category: 'pipeline' },
  { type: 'kafka_connect',  display_name: 'Kafka Connect',    category: 'pipeline' },
  { type: 'nifi',           display_name: 'NiFi',             category: 'pipeline' },
  { type: 'openlineage',    display_name: 'OpenLineage',      category: 'pipeline' },
  { type: 'spline',         display_name: 'Spline',           category: 'pipeline' },
  { type: 'wherescape',     display_name: 'Wherescape',       category: 'pipeline' },

  // ML Model
  { type: 'mlflow',         display_name: 'MLflow',           category: 'ml_model' },
  { type: 'sagemaker',      display_name: 'SageMaker',        category: 'ml_model' },

  // Storage
  { type: 'gcs_storage',    display_name: 'GCS',              category: 'storage' },
  { type: 's3_storage',     display_name: 'S3 Storage',       category: 'storage' },

  // Search
  { type: 'elasticsearch',  display_name: 'Elasticsearch',    category: 'search' },
  { type: 'opensearch',     display_name: 'OpenSearch',       category: 'search' },

  // Drive
  { type: 'sftp',           display_name: 'SFTP',             category: 'drive' },
  { type: 'custom_drive',   display_name: 'Custom Drive',     category: 'drive' },

  // Metadata
  { type: 'alation_sink',   display_name: 'Alation',          category: 'metadata' },
  { type: 'amundsen',       display_name: 'Amundsen',         category: 'metadata' },
  { type: 'atlas',          display_name: 'Atlas',            category: 'metadata' },

  // API
  { type: 'rest',           display_name: 'REST',             category: 'api' },
];

// Default config templates per connector type for the JSON editor placeholder
export const CONFIG_TEMPLATES: Partial<Record<string, object>> = {
  postgres:      { host: 'localhost', port: 5432, database: 'mydb', username: 'user', password: '' },
  mysql:         { host: 'localhost', port: 3306, database: 'mydb', username: 'user', password: '' },
  mariadb:       { host: 'localhost', port: 3306, database: 'mydb', username: 'user', password: '' },
  mssql:         { host: 'localhost', port: 1433, database: 'mydb', username: 'user', password: '' },
  oracle:        { host: 'localhost', port: 1521, service_name: 'ORCL', username: 'user', password: '', thick_mode: false, oracle_client_path: '' },
  oracle_erp:    {
    base_url: 'https://your-pod.fa.ocs.oraclecloud.com',
    username: 'user',
    password: '',
    module: 'Financials',
    resources: [
      { module: 'Financials', name: 'Invoices', path: '/fscmRestApi/resources/latest/invoices' },
      { module: 'Procurement', name: 'PurchaseOrders', path: '/fscmRestApi/resources/latest/purchaseOrders' }
    ]
  },
  sqlite:        { database_path: '/path/to/file.db' },
  snowflake:     { account: 'account.region', username: 'user', password: '', warehouse: 'COMPUTE_WH', database: 'mydb', schema: 'PUBLIC' },
  bigquery:      { project: 'my-project', dataset: 'my_dataset', credentials_path: '/path/to/creds.json' },
  redshift:      { host: 'cluster.region.redshift.amazonaws.com', port: 5439, database: 'mydb', username: 'user', password: '' },
  athena:        { s3_staging_dir: 's3://bucket/prefix/', region: 'us-east-1', database: 'default' },
  databricks:    { host: 'adb-xxx.azuredatabricks.net', http_path: '/sql/1.0/warehouses/xxx', token: '' },
  mongodb:       { host: 'localhost', port: 27017, database: 'mydb', username: 'user', password: '' },
  dynamodb:      { region: 'us-east-1', access_key_id: '', secret_access_key: '' },
  clickhouse:    { host: 'localhost', port: 8123, database: 'default', username: 'default', password: '' },
  hive:          { host: 'localhost', port: 10000, database: 'default', username: 'user' },
  kafka:         { bootstrap_servers: 'localhost:9092', topic_pattern: '.*' },
  kinesis:       { region: 'us-east-1', access_key_id: '', secret_access_key: '' },
  redpanda:      { bootstrap_servers: 'localhost:9092' },
  s3_storage:    { bucket_name: 'my-bucket', region: 'us-east-1', access_key_id: '', secret_access_key: '' },
  gcs_storage:   { bucket_name: 'my-bucket', project: 'my-project', credentials_path: '/path/to/creds.json' },
  elasticsearch: { hosts: ['http://localhost:9200'], username: '', password: '' },
  opensearch:    { hosts: ['http://localhost:9200'], username: '', password: '' },
  tableau:       { server: 'https://tableau.example.com', site: '', username: '', password: '' },
  powerbi:       { client_id: '', client_secret: '', tenant_id: '' },
  looker:        { client_id: '', client_secret: '', base_url: 'https://company.looker.com' },
  metabase:      { host: 'http://localhost:3000', username: '', password: '' },
  superset:      { host: 'http://localhost:8088', username: 'admin', password: '' },
  grafana:       { host: 'http://localhost:3000', api_key: '' },
  airflow:       { host: 'http://localhost:8080', username: 'admin', password: '' },
  mlflow:        { tracking_uri: 'http://localhost:5000' },
  sagemaker:     { region: 'us-east-1', access_key_id: '', secret_access_key: '' },
  rest:          { host: 'https://api.example.com', token: '' },
  sftp:          { host: 'sftp.example.com', port: 22, username: 'user', password: '' },
};

export function getConfigTemplate(type: string): string {
  const tpl = CONFIG_TEMPLATES[type] ?? {};
  return JSON.stringify(tpl, null, 2);
}

export const CONNECTORS_BY_CATEGORY: Record<ConnectorCategory, Connector[]> = (() => {
  const map = {} as Record<ConnectorCategory, Connector[]>;
  for (const c of CONNECTORS) {
    (map[c.category] ??= []).push(c);
  }
  return map;
})();
