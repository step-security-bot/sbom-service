-- Data only for test environment

INSERT INTO product_type VALUES
('MaJun')
ON CONFLICT (type) DO NOTHING;

INSERT INTO product_config(id, name, label, ord, product_type)
VALUES
('3d686c39-4417-4f90-ab03-03772eaa51a5', 'productName', '软件名', 1, 'MaJun')
ON CONFLICT (id) DO UPDATE
    SET name = EXCLUDED.name, label = EXCLUDED.label, ord = EXCLUDED.ord, product_type = EXCLUDED.product_type;

INSERT INTO product_config_value(id, value, label, product_config_id)
VALUES
('a5c1a2c0-6b08-41c3-917a-725ec834316d', 'anti', 'anti', '3d686c39-4417-4f90-ab03-03772eaa51a5'),
('76bb4f29-519f-4117-ac45-4bc24929e3f2', 'ci-api-gateway-service', 'ci-api-gateway-service', '3d686c39-4417-4f90-ab03-03772eaa51a5'),
('0b31c3f9-900c-48c5-b1fd-1f87ab0bb123', 'ci-backend-service', 'ci-backend-service', '3d686c39-4417-4f90-ab03-03772eaa51a5'),
('928acead-88d8-40ec-a08d-356bb464ea0a', 'ci-portal-service', 'ci-portal-service', '3d686c39-4417-4f90-ab03-03772eaa51a5'),
('9b99a009-de70-4215-8712-16fd981780a2', 'cloudsca-analysis', 'cloudsca-analysis', '3d686c39-4417-4f90-ab03-03772eaa51a5'),
('5a84a0b4-604d-42b4-ad41-6eb5712b838f', 'cloudsca-api-gw', 'cloudsca-api-gw', '3d686c39-4417-4f90-ab03-03772eaa51a5'),
('34a4a679-bd92-4bc4-b14c-c659ad9455fd', 'cloudsca-data-manager', 'cloudsca-data-manager', '3d686c39-4417-4f90-ab03-03772eaa51a5'),
('3d2c357e-dd64-4d4c-aac5-7ac9f375553a', 'cloudsca-eureka', 'cloudsca-eureka', '3d686c39-4417-4f90-ab03-03772eaa51a5'),
('c1f62ff1-a352-41fc-82a0-eefc223a91e1', 'cloudsca-gateway', 'cloudsca-gateway', '3d686c39-4417-4f90-ab03-03772eaa51a5'),
('8dda628d-4552-4f69-a2ca-50a2b61bfa62', 'cloudsca-model', 'cloudsca-model', '3d686c39-4417-4f90-ab03-03772eaa51a5')
ON CONFLICT (id) DO UPDATE
    SET value = EXCLUDED.value, label = EXCLUDED.label, product_config_id = EXCLUDED.product_config_id;

INSERT INTO product(id, name, attribute)
VALUES
('26df1082-3715-47b6-ab3a-278aec66f65d', 'anti', '{"productType": "MaJun", "productName": "anti"}'::jsonb),
('b94a5074-7cae-4973-b4b1-decadd027c9a', 'ci-api-gateway-service', '{"productType": "MaJun", "productName": "ci-api-gateway-service"}'::jsonb),
('c9dd6abf-2b52-42f3-b4dd-fab25fd310d0', 'ci-backend-service', '{"productType": "MaJun", "productName": "ci-backend-service"}'::jsonb),
('9dbd5263-d034-4715-b95d-972769da5343', 'ci-portal-service', '{"productType": "MaJun", "productName": "ci-portal-service"}'::jsonb),
('e8e8c2af-7cdb-43f3-a610-350af90c465f', 'cloudsca-analysis', '{"productType": "MaJun", "productName": "cloudsca-analysis"}'::jsonb),
('4ce1f13a-3091-4003-bf30-d1da73fb2f16', 'cloudsca-api-gw', '{"productType": "MaJun", "productName": "cloudsca-api-gw"}'::jsonb),
('d71c5897-1f63-4753-b77d-0eaf3d11a413', 'cloudsca-data-manager', '{"productType": "MaJun", "productName": "cloudsca-data-manager"}'::jsonb),
('6c18a540-0c26-4f12-94f2-97a570eac490', 'cloudsca-eureka', '{"productType": "MaJun", "productName": "cloudsca-eureka"}'::jsonb),
('f530b3f1-8f83-443e-b6f2-aefce3c095b5', 'cloudsca-gateway', '{"productType": "MaJun", "productName": "cloudsca-gateway"}'::jsonb),
('ac462351-539a-42db-b389-19766f400fff', 'cloudsca-model', '{"productType": "MaJun", "productName": "cloudsca-model"}'::jsonb)
ON CONFLICT (id) DO UPDATE
    SET name = EXCLUDED.name, attribute = EXCLUDED.attribute;
