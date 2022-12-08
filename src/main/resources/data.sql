BEGIN;

-- Init table index(json field)
CREATE INDEX IF NOT EXISTS external_purl_ref_purl_idx ON external_purl_ref USING btree (jsonb_extract_path_text ( purl,'type'), jsonb_extract_path_text ( purl,'name'));

-- Alter
ALTER TABLE product_config DROP COLUMN IF EXISTS value_type;

-- Init table product_type
INSERT INTO product_type VALUES
('openEuler'),
('MindSpore'),
('openGauss'),
('OpenHarmony')
ON CONFLICT (type) DO NOTHING;

-- Init table product_config
--openEuler
INSERT INTO product_config(id, name, label, ord, product_type)
VALUES
('013d61a1-5938-46db-9092-88df47c10bf6', 'version', '版本号', 1, 'openEuler'),
('f0266c11-1d7a-45c6-80e6-2ccf586f6755', 'imageFormat', '文件格式', 2, 'openEuler'),
('7f959c6b-6651-4c56-be30-5e2cebb901cf', 'imageType', '镜像类型', 3, 'openEuler'),
('5263c064-4d04-4232-a717-eb84499b5f5f', 'arch', '系统架构', 4, 'openEuler')
ON CONFLICT (id) DO UPDATE
    SET name = EXCLUDED.name, label = EXCLUDED.label, ord = EXCLUDED.ord, product_type = EXCLUDED.product_type;

-- MindSpore
INSERT INTO product_config(id, name, label, ord, product_type)
VALUES
('0eccda6b-72d4-4868-a257-baef0eac193f', 'productName', '软件名', 1, 'MindSpore'),
('d96a0380-d9c0-4176-bbd6-9578952636f6', 'version', '版本号', 2, 'MindSpore'),
('a4e710c7-6811-4626-b32b-ae067fade540', 'platform', '硬件平台', 3, 'MindSpore'),
('327af62f-9689-4dd4-a1ff-b8ff7ad0bd61', 'os', '操作系统', 4, 'MindSpore'),
('75e5459b-b969-49e7-9d68-f2f346eb2120', 'arch', '系统架构', 5, 'MindSpore'),
('e471690e-69a1-4646-8868-036e53d702c6', 'language', '编程语言', 6, 'MindSpore')
ON CONFLICT (id) DO UPDATE
    SET name = EXCLUDED.name, label = EXCLUDED.label, ord = EXCLUDED.ord, product_type = EXCLUDED.product_type;

-- openGauss
INSERT INTO product_config(id, name, label, ord, product_type)
VALUES
('8f27d9b1-696b-4700-9fc0-385a45fc0c56', 'productName', '软件名', 1, 'openGauss'),
('527a8727-2d7e-4db4-b138-acb33405e447', 'version', '版本号', 2, 'openGauss'),
('243452d3-da07-4fab-ad74-8767629528fa', 'os', '操作系统', 3, 'openGauss'),
('c589facd-4ac6-441d-b8fa-a787ea60c18e', 'arch', '系统架构', 4, 'openGauss')
ON CONFLICT (id) DO UPDATE
    SET name = EXCLUDED.name, label = EXCLUDED.label, ord = EXCLUDED.ord, product_type = EXCLUDED.product_type;

-- OpenHarmony
INSERT INTO product_config(id, name, label, ord, product_type)
VALUES
('f7856269-0339-4fe7-80fa-de15042d40d9', 'version', '版本号', 1, 'OpenHarmony')
ON CONFLICT (id) DO UPDATE
    SET name = EXCLUDED.name, label = EXCLUDED.label, ord = EXCLUDED.ord, product_type = EXCLUDED.product_type;

-- Init table product_config_value
--openEuler
INSERT INTO product_config_value(id, value, label, product_config_id)
VALUES
('2db9d338-6759-4b8b-95a4-cda6a8c11b1c', 'openEuler-22.03-LTS', 'openEuler-22.03-LTS', '013d61a1-5938-46db-9092-88df47c10bf6'),
('bcf54a11-c8b6-42ca-8978-bf08ffe80320', 'openEuler-20.03-LTS-SP1', 'openEuler-20.03-LTS-SP1', '013d61a1-5938-46db-9092-88df47c10bf6'),
('7ded4e5d-2b3e-44a4-bbbf-07d582e5d471', 'openEuler-20.03-LTS-SP2', 'openEuler-20.03-LTS-SP2', '013d61a1-5938-46db-9092-88df47c10bf6'),
('cd516d5f-158a-4bd5-85d3-231b0dd7790a', 'openEuler-20.03-LTS-SP3', 'openEuler-20.03-LTS-SP3','013d61a1-5938-46db-9092-88df47c10bf6')
ON CONFLICT (id) DO UPDATE
    SET value = EXCLUDED.value, label = EXCLUDED.label, product_config_id = EXCLUDED.product_config_id;

INSERT INTO product_config_value(id, value, label, product_config_id)
VALUES
('fdd5eca2-ff82-4466-b885-033af961efe9', 'ISO', 'ISO', 'f0266c11-1d7a-45c6-80e6-2ccf586f6755'),
('120e0d76-4c26-4d67-a776-f105eb40aadd', 'EPOL', 'EPOL', 'f0266c11-1d7a-45c6-80e6-2ccf586f6755')
ON CONFLICT (id) DO UPDATE
    SET value = EXCLUDED.value, label = EXCLUDED.label, product_config_id = EXCLUDED.product_config_id;

INSERT INTO product_config_value(id, value, label, product_config_id)
VALUES
('764109ae-5b97-4779-9fa2-dec16e8a8549', 'Everything', 'Everything', '7f959c6b-6651-4c56-be30-5e2cebb901cf'),
('a5261530-1176-4c96-a279-33dbf0e9fe3a', 'Normal', 'Normal', '7f959c6b-6651-4c56-be30-5e2cebb901cf'),
('4dd4b407-d688-4559-91d6-d19ebd830f79', 'Update', 'Update', '7f959c6b-6651-4c56-be30-5e2cebb901cf'),
('afc77883-3f39-4b72-bb22-ca9cb14dc405', 'Update Train', 'Update Train', '7f959c6b-6651-4c56-be30-5e2cebb901cf'),
('fd65fc88-aa4f-4176-8008-2b605df223ce', 'Update Wallaby', 'Update Wallaby', '7f959c6b-6651-4c56-be30-5e2cebb901cf')
ON CONFLICT (id) DO UPDATE
    SET value = EXCLUDED.value, label = EXCLUDED.label, product_config_id = EXCLUDED.product_config_id;

INSERT INTO product_config_value(id, value, label, product_config_id)
VALUES
('e2537af8-3740-4066-88f2-22da2d23fe2e', 'aarch64', 'aarch64', '5263c064-4d04-4232-a717-eb84499b5f5f'),
('2e534ddd-ced4-440f-a80d-697c5ec8990f', 'x86_64', 'x86_64', '5263c064-4d04-4232-a717-eb84499b5f5f')
ON CONFLICT (id) DO UPDATE
    SET value = EXCLUDED.value, label = EXCLUDED.label, product_config_id = EXCLUDED.product_config_id;

--MindSpore
INSERT INTO product_config_value(id, value, label, product_config_id)
VALUES
('8a1b0324-e1b9-4288-b98c-141651b9b9ad', 'MindSpore', 'MindSpore', '0eccda6b-72d4-4868-a257-baef0eac193f')
ON CONFLICT (id) DO UPDATE
    SET value = EXCLUDED.value, label = EXCLUDED.label, product_config_id = EXCLUDED.product_config_id;

INSERT INTO product_config_value(id, value, label, product_config_id)
VALUES('b96e35b0-a375-4f2c-bb04-b6bfa11610ce', '1.8.0', '1.8.0', 'd96a0380-d9c0-4176-bbd6-9578952636f6')
ON CONFLICT (id) DO UPDATE
    SET value = EXCLUDED.value, label = EXCLUDED.label, product_config_id = EXCLUDED.product_config_id;

INSERT INTO product_config_value(id, value, label, product_config_id)
VALUES('2d449fe0-5b3a-44f7-8d90-71a41da21b2f', 'CPU', 'CPU', 'a4e710c7-6811-4626-b32b-ae067fade540')
ON CONFLICT (id) DO UPDATE
    SET value = EXCLUDED.value, label = EXCLUDED.label, product_config_id = EXCLUDED.product_config_id;

INSERT INTO product_config_value(id, value, label, product_config_id)
VALUES('56a561e8-3cc5-4700-af5b-782a6155708c', 'Linux', 'Linux', '327af62f-9689-4dd4-a1ff-b8ff7ad0bd61')
ON CONFLICT (id) DO UPDATE
    SET value = EXCLUDED.value, label = EXCLUDED.label, product_config_id = EXCLUDED.product_config_id;

INSERT INTO product_config_value(id, value, label, product_config_id)
VALUES
('254b7b04-f76f-474f-834e-282ababab7f7', 'aarch64', 'aarch64', '75e5459b-b969-49e7-9d68-f2f346eb2120'),
('17b26f4e-4dfc-4c0d-b037-4fd8236e1c94', 'x86_64', 'x86_64', '75e5459b-b969-49e7-9d68-f2f346eb2120')
ON CONFLICT (id) DO UPDATE
    SET value = EXCLUDED.value, label = EXCLUDED.label, product_config_id = EXCLUDED.product_config_id;

INSERT INTO product_config_value(id, value, label, product_config_id)
VALUES
('72b97f5a-5028-4c67-8111-017740b8cd8c', 'Python 3.7', 'Python 3.7', 'e471690e-69a1-4646-8868-036e53d702c6'),
('4e2755bd-8d6e-4322-9c32-2e5d803a08e3', 'Python 3.8', 'Python 3.8', 'e471690e-69a1-4646-8868-036e53d702c6'),
('f892af99-77ee-4fd9-89ee-97e06274022a', 'Python 3.9', 'Python 3.9', 'e471690e-69a1-4646-8868-036e53d702c6')
ON CONFLICT (id) DO UPDATE
    SET value = EXCLUDED.value, label = EXCLUDED.label, product_config_id = EXCLUDED.product_config_id;

-- openGauss
INSERT INTO product_config_value(id, value, label, product_config_id)
VALUES
('372c2093-83ec-418c-97f2-fdf6373e36a9', 'openGauss Enterprise-Edition', 'openGauss Enterprise-Edition', '8f27d9b1-696b-4700-9fc0-385a45fc0c56'),
('33e5cbf3-c1ff-4eb2-8857-a497b495fce8', 'openGauss Simplified', 'openGauss Simplified', '8f27d9b1-696b-4700-9fc0-385a45fc0c56'),
('8282f0a2-873b-4941-a077-a1c8e0d56a07', 'openGauss Lite', 'openGauss Lite', '8f27d9b1-696b-4700-9fc0-385a45fc0c56'),
('d4d8f4e1-2836-4337-a15e-12a40518aeed', 'openGauss JDBC', 'openGauss JDBC', '8f27d9b1-696b-4700-9fc0-385a45fc0c56'),
('1afd7a75-3a93-43e9-a5a9-ead4a4b077b5', 'openGauss Python-psycopg2', 'openGauss Python-psycopg2', '8f27d9b1-696b-4700-9fc0-385a45fc0c56'),
('8c813871-5272-4d9b-8a9a-7f4fd8b94de0', 'Data Studio', 'Data Studio', '8f27d9b1-696b-4700-9fc0-385a45fc0c56'),
('3ddfdcaf-8588-481b-bec7-0112e204c177', 'Chameleon', 'Chameleon', '8f27d9b1-696b-4700-9fc0-385a45fc0c56'),
('cacdf592-c8d0-4cc1-87b9-aa64ffb52598', 'Online Migration', 'Online Migration', '8f27d9b1-696b-4700-9fc0-385a45fc0c56'),
('e2178149-4da2-487d-9095-70a6e8181337', 'Reverse Migration', 'Reverse Migration', '8f27d9b1-696b-4700-9fc0-385a45fc0c56'),
('44140167-8719-4bc8-a173-97f342a0a22b', 'Data Checker', 'Data Checker', '8f27d9b1-696b-4700-9fc0-385a45fc0c56')
ON CONFLICT (id) DO UPDATE
    SET value = EXCLUDED.value, label = EXCLUDED.label, product_config_id = EXCLUDED.product_config_id;

INSERT INTO product_config_value(id, value, label, product_config_id)
VALUES
('600e3be9-725e-4d84-a1dc-0f147cd7d728', '3.1.0', '3.1.0', '527a8727-2d7e-4db4-b138-acb33405e447')
ON CONFLICT (id) DO UPDATE
    SET value = EXCLUDED.value, label = EXCLUDED.label, product_config_id = EXCLUDED.product_config_id;

INSERT INTO product_config_value(id, value, label, product_config_id)
VALUES
('7aef27c1-a7e3-46ae-a357-c83dd7f52a02', 'CentOS', 'CentOS', '243452d3-da07-4fab-ad74-8767629528fa'),
('3f2f041a-db8c-4fca-9123-7adae62b5dd4', 'openEuler', 'openEuler', '243452d3-da07-4fab-ad74-8767629528fa')
ON CONFLICT (id) DO UPDATE
    SET value = EXCLUDED.value, label = EXCLUDED.label, product_config_id = EXCLUDED.product_config_id;

INSERT INTO product_config_value(id, value, label, product_config_id)
VALUES
('b66a2815-4821-433b-a8f7-a07c0e86e0b5', 'aarch64', 'aarch64', 'c589facd-4ac6-441d-b8fa-a787ea60c18e'),
('0ceb1360-0743-49bb-9d63-ebcd7c75f3f0', 'x86_64', 'x86_64', 'c589facd-4ac6-441d-b8fa-a787ea60c18e')
ON CONFLICT (id) DO UPDATE
    SET value = EXCLUDED.value, label = EXCLUDED.label, product_config_id = EXCLUDED.product_config_id;

-- OpenHarmony
INSERT INTO product_config_value(id, value, label, product_config_id)
VALUES('da6b13a9-edb6-43d8-8b63-f6859abcadef', 'OpenHarmony-v3.1-Release', 'OpenHarmony-v3.1-Release', 'f7856269-0339-4fe7-80fa-de15042d40d9')
ON CONFLICT (id) DO UPDATE
    SET value = EXCLUDED.value, label = EXCLUDED.label, product_config_id = EXCLUDED.product_config_id;

-- Insert openEuler products
INSERT INTO product(id, name, attribute)
VALUES
('4a34d4b7-25ce-4c8d-b2f7-9d210a6dd32c', 'openEuler-22.03-LTS-x86_64-dvd.iso', '{"productType":"openEuler", "version":"openEuler-22.03-LTS","imageFormat":"ISO","imageType":"Normal","arch":"x86_64"}'::jsonb),
('55dfefff-ec35-49f4-b395-de3824605bbc', 'openEuler-22.03-LTS-everything-x86_64-dvd.iso', '{"productType":"openEuler", "version":"openEuler-22.03-LTS","imageFormat":"ISO","imageType":"Everything","arch":"x86_64"}'::jsonb),
('a51b9584-e7af-47cb-9f96-fa112e234648', '/openEuler-22.03-LTS/update/x86_64', '{"productType":"openEuler", "version":"openEuler-22.03-LTS","imageFormat":"ISO","imageType":"Update","arch":"x86_64"}'::jsonb),
('7b114872-0518-436f-bf23-c21d5eaf3bbb', 'openEuler-22.03-LTS-aarch64-dvd.iso', '{"productType":"openEuler", "version":"openEuler-22.03-LTS","imageFormat":"ISO","imageType":"Normal","arch":"aarch64"}'::jsonb),
('96d17128-644e-4019-bff1-40516d97ab31', 'openEuler-22.03-LTS-everything-aarch64-dvd.iso', '{"productType":"openEuler", "version":"openEuler-22.03-LTS","imageFormat":"ISO","imageType":"Everything","arch":"aarch64"}'::jsonb),
('7f1cd2d8-f81f-4816-854d-20f2d85348eb', '/openEuler-22.03-LTS/update/aarch64', '{"productType":"openEuler", "version":"openEuler-22.03-LTS","imageFormat":"ISO","imageType":"Update","arch":"aarch64"}'::jsonb),
('f71b86c2-3d0c-4e9a-a9eb-b1bad0213d02', '/openEuler-22.03-LTS/EPOL/update/multi_version/OpenStack/Wallaby/aarch64', '{"productType":"openEuler", "version":"openEuler-22.03-LTS","imageFormat":"EPOL","imageType":"Update Wallaby","arch":"aarch64"}'::jsonb),
('d8c855f8-6df0-4149-8b29-155e1714c6a7', '/openEuler-22.03-LTS/EPOL/update/multi_version/OpenStack/Wallaby/x86_64', '{"productType":"openEuler", "version":"openEuler-22.03-LTS","imageFormat":"EPOL","imageType":"Update Wallaby","arch":"x86_64"}'::jsonb),
('c4599563-e78a-488e-8cb7-5ff53ebf5eb7', '/openEuler-22.03-LTS/EPOL/update/multi_version/OpenStack/Train/aarch64', '{"productType":"openEuler", "version":"openEuler-22.03-LTS","imageFormat":"EPOL","imageType":"Update Train","arch":"aarch64"}'::jsonb),
('ae7201b8-8548-463b-ac2e-b8a6cd6610da', '/openEuler-22.03-LTS/EPOL/update/multi_version/OpenStack/Train/x86_64', '{"productType":"openEuler", "version":"openEuler-22.03-LTS","imageFormat":"EPOL","imageType":"Update Train","arch":"x86_64"}'::jsonb),
('9bdab31c-a7bd-4383-b0c5-16d28e148e43', '/openEuler-20.03-LTS-SP3/update/aarch64', '{"productType":"openEuler", "version":"openEuler-20.03-LTS-SP3","imageFormat":"ISO","imageType":"Update","arch":"aarch64"}'::jsonb),
('27516015-2c95-4f1e-ada9-926dc3ffad03', '/openEuler-20.03-LTS-SP3/update/x86_64', '{"productType":"openEuler", "version":"openEuler-20.03-LTS-SP3","imageFormat":"ISO","imageType":"Update","arch":"x86_64"}'::jsonb),
('797d8d29-7cab-4468-ba02-7e0078fee5a5', '/openEuler-20.03-LTS-SP3/EPOL/update/main/aarch64', '{"productType":"openEuler", "version":"openEuler-20.03-LTS-SP3","imageFormat":"EPOL","imageType":"Update","arch":"aarch64"}'::jsonb),
('55540832-de6c-49c0-b3f2-b4b62e8569ad', '/openEuler-20.03-LTS-SP3/EPOL/update/main/x86_64', '{"productType":"openEuler", "version":"openEuler-20.03-LTS-SP3","imageFormat":"EPOL","imageType":"Update","arch":"x86_64"}'::jsonb),
('ae9f6ef1-66c8-44dd-965e-2471d52da765', '/openEuler-20.03-LTS-SP2/update/aarch64', '{"productType":"openEuler", "version":"openEuler-20.03-LTS-SP2","imageFormat":"ISO","imageType":"Update","arch":"aarch64"}'::jsonb),
('a9f04d75-433e-476d-b1c7-6a64a7feb8c3', '/openEuler-20.03-LTS-SP2/update/x86_64', '{"productType":"openEuler", "version":"openEuler-20.03-LTS-SP2","imageFormat":"ISO","imageType":"Update","arch":"x86_64"}'::jsonb),
('2adb6add-d69b-4f29-9233-86c29a205250', '/openEuler-20.03-LTS-SP2/EPOL/update/main/aarch64', '{"productType":"openEuler", "version":"openEuler-20.03-LTS-SP2","imageFormat":"EPOL","imageType":"Update","arch":"aarch64"}'::jsonb),
('93887c35-5a21-4d6a-bf9f-8158a17adcb3', '/openEuler-20.03-LTS-SP2/EPOL/update/main/x86_64', '{"productType":"openEuler", "version":"openEuler-20.03-LTS-SP2","imageFormat":"EPOL","imageType":"Update","arch":"x86_64"}'::jsonb),
('d22c6135-1506-4c29-bbc3-167f94fdb38d', '/openEuler-20.03-LTS-SP1/update/aarch64', '{"productType":"openEuler", "version":"openEuler-20.03-LTS-SP1","imageFormat":"ISO","imageType":"Update","arch":"aarch64"}'::jsonb),
('b127e9ad-42ca-46c5-8777-9cd946de0e0a', '/openEuler-20.03-LTS-SP1/update/x86_64', '{"productType":"openEuler", "version":"openEuler-20.03-LTS-SP1","imageFormat":"ISO","imageType":"Update","arch":"x86_64"}'::jsonb),
('e50d0398-2516-4ab4-88d6-9199662a710a', '/openEuler-20.03-LTS-SP1/EPOL/update/aarch64', '{"productType":"openEuler", "version":"openEuler-20.03-LTS-SP1","imageFormat":"EPOL","imageType":"Update","arch":"aarch64"}'::jsonb),
('ae05237c-9d45-4fe0-afe3-a5fbf7004686', '/openEuler-20.03-LTS-SP1/EPOL/update/x86_64', '{"productType":"openEuler", "version":"openEuler-20.03-LTS-SP1","imageFormat":"EPOL","imageType":"Update","arch":"x86_64"}'::jsonb)
ON CONFLICT (id) DO UPDATE
    SET name = EXCLUDED.name, attribute = EXCLUDED.attribute;

-- Insert MindSpore products
INSERT INTO product(id, name, attribute)
VALUES
('e686d5ba-cd30-41e7-b97a-a3481bb6e0a2', 'mindspore-1.8.0-cp37-cp37m-linux_x86_64.whl', '{"productType": "MindSpore", "productName": "MindSpore", "version": "1.8.0","platform": "CPU", "os": "Linux", "arch": "x86_64", "language": "Python 3.7"}'::jsonb)
ON CONFLICT (id) DO UPDATE
    SET name = EXCLUDED.name, attribute = EXCLUDED.attribute;

-- Insert openGauss products
INSERT INTO product(id, name, attribute)
VALUES
('6c1bca0c-b8f2-40f5-90fe-75a376430748', 'x86/openGauss-3.1.0-CentOS-64bit-all.tar.gz', '{"productType": "openGauss", "productName": "openGauss Enterprise-Edition", "version": "3.1.0", "os": "CentOS", "arch": "x86_64"}'::jsonb),
('89776ab6-3493-4057-a192-aa5796709bc1', 'x86/openGauss-3.1.0-CentOS-64bit.tar.bz2', '{"productType": "openGauss", "productName": "openGauss Simplified", "version": "3.1.0", "os": "CentOS", "arch": "x86_64"}'::jsonb),
('6aef07c9-ab24-4fb0-b319-c9209f817cef', 'x86/openGauss-Lite-3.1.0-CentOS-x86_64.tar.gz', '{"productType": "openGauss", "productName": "openGauss Lite", "version": "3.1.0", "os": "CentOS", "arch": "x86_64"}'::jsonb),
('99264359-6450-45e3-b174-17bd012f3a01', 'arm/openGauss-3.1.0-openEuler-64bit-all.tar.gz', '{"productType": "openGauss", "productName": "openGauss Enterprise-Edition", "version": "3.1.0", "os": "openEuler", "arch": "aarch64"}'::jsonb),
('2899d9e2-dc03-4345-8860-ae5ee6fb94ec', 'arm/openGauss-3.1.0-openEuler-64bit.tar.bz2', '{"productType": "openGauss", "productName": "openGauss Simplified", "version": "3.1.0", "os": "openEuler", "arch": "aarch64"}'::jsonb),
('8d61701a-5f3b-43b4-a391-6a4116f4a484', 'arm/openGauss-Lite-3.1.0-openEuler-aarch64.tar.gz', '{"productType": "openGauss", "productName": "openGauss Lite", "version": "3.1.0", "os": "openEuler", "arch": "aarch64"}'::jsonb),
('7e11957d-f8da-4230-961d-3e89fd7a833e', 'x86_openEuler/openGauss-3.1.0-openEuler-64bit-all.tar.gz', '{"productType": "openGauss", "productName": "openGauss Enterprise-Edition", "version": "3.1.0", "os": "openEuler", "arch": "x86_64"}'::jsonb),
('2e960119-e5ae-4a8a-b251-fe918f407c0d', 'x86_openEuler/openGauss-3.1.0-openEuler-64bit.tar.bz2', '{"productType": "openGauss", "productName": "openGauss Simplified", "version": "3.1.0", "os": "openEuler", "arch": "x86_64"}'::jsonb),
('fe908dc5-bc8d-4213-b91c-8b88f7bee0b5', 'x86_openEuler/openGauss-Lite-3.1.0-openEuler-x86_64.tar.gz', '{"productType": "openGauss", "productName": "openGauss Lite", "version": "3.1.0", "os": "openEuler", "arch": "x86_64"}'::jsonb),
('e0666636-d8af-4cd1-9f04-cdc76d18c13b', 'x86/openGauss-3.1.0-JDBC.tar.gz', '{"productType": "openGauss", "productName": "openGauss JDBC", "version": "3.1.0", "os": "CentOS", "arch": "x86_64"}'::jsonb),
('69b9ce97-5be9-427f-b4a0-825ab1ee9070', 'arm/openGauss-3.1.0-JDBC.tar.gz', '{"productType": "openGauss", "productName": "openGauss JDBC", "version": "3.1.0", "os": "openEuler", "arch": "aarch64"}'::jsonb),
('f5aa7756-154b-499c-814d-662eb70855d5', 'x86_openEuler/openGauss-3.1.0-JDBC.tar.gz', '{"productType": "openGauss", "productName": "openGauss JDBC", "version": "3.1.0", "os": "openEuler", "arch": "x86_64"}'::jsonb),
('5169272f-4d19-44c3-8c55-e57f164d399e', 'x86/openGauss-3.1.0-CentOS-x86_64-Python.tar.gz', '{"productType": "openGauss", "productName": "openGauss Python-psycopg2", "version": "3.1.0", "os": "CentOS", "arch": "x86_64"}'::jsonb),
('b676a0e5-6838-4c9f-923f-308f25ab0c37', 'arm/openGauss-3.1.0-openEuler-aarch64-Python.tar.gz', '{"productType": "openGauss", "productName": "openGauss Python-psycopg2", "version": "3.1.0", "os": "openEuler", "arch": "aarch64"}'::jsonb),
('a4794e73-1197-4b49-9ab6-8bca49bf24d0', 'x86_openEuler/openGauss-3.1.0-openEuler-x86_64-Python.tar.gz', '{"productType": "openGauss", "productName": "openGauss Python-psycopg2", "version": "3.1.0", "os": "openEuler", "arch": "x86_64"}'::jsonb),
('3f391dfb-3986-47db-8bcb-3649c63b40b8', 'tools/DataStudio_win_64.zip', '{"productType": "openGauss", "productName": "Data Studio", "version": "3.1.0"}'::jsonb),
('278c3713-6ec9-4c42-9b5a-b2028e6dc256', 'tools/chameleon-3.1.0-py3-none-any.whl', '{"productType": "openGauss", "productName": "Chameleon", "version": "3.1.0"}'::jsonb),
('6002ae95-e595-46f7-ac74-7ff7d1b8c7c9', 'tools/online-migration-mysql2openGauss-3.1.0.tar.gz', '{"productType": "openGauss", "productName": "Online Migration", "version": "3.1.0"}'::jsonb),
('136e382f-2a18-4fc8-86ad-e55a83e70946', 'tools/openGauss-reverse-migration-mysql-3.1.0.tar.gz', '{"productType": "openGauss", "productName": "Reverse Migration", "version": "3.1.0"}'::jsonb),
('7ca73c8e-ee2e-4a6f-89ec-0f42c01a3c5a', 'tools/openGauss-datachecker-performance-3.1.0.tar.gz', '{"productType": "openGauss", "productName": "Data Checker", "version": "3.1.0"}'::jsonb)
ON CONFLICT (id) DO UPDATE
    SET name = EXCLUDED.name, attribute = EXCLUDED.attribute;

-- OpenHarmony
INSERT INTO product(id, name, attribute)
VALUES
('65d0a8d7-94ee-4f98-9992-889187e53206', 'harmonyos/os/3.1-Release/standard_hi3516.tar.gz', '{"productType": "OpenHarmony", "version": "OpenHarmony-v3.1-Release"}'::jsonb)
ON CONFLICT (id) DO UPDATE
    SET name = EXCLUDED.name, attribute = EXCLUDED.attribute;

-- Assertions
-- Hibernate can't recognize $$ delimiter, so use ' as delimiter instead

-- Assert 'productType' attribute is in 'attribute' jsonb column of table 'product' and is valid
DO '
DECLARE
	product_id UUID;
	product_type_attr_exist BOOL;
	pt TEXT;
	product_types TEXT[];
BEGIN
	SELECT array_agg(type) INTO product_types FROM product_type;
	FOR product_id IN SELECT id FROM product
	LOOP
		SELECT jsonb_path_exists(attribute, ''$.productType'') INTO product_type_attr_exist FROM product p WHERE p.id = product_id;
		ASSERT product_type_attr_exist IS TRUE, format(''productType of product [%s] is missing'', product_id);
		SELECT p.attribute ->> ''productType'' INTO pt FROM product p WHERE p.id = product_id;
		assert pt = ANY(product_types), format(''productType [%s] of product [%s] is invalid'', pt, product_id);
	END LOOP;
END ';

-- Assert keys in 'attribute' jsonb column of table 'product' are all in 'product_config' table
DO '
DECLARE
	config_names TEXT[];
	product_config_names TEXT[];
	pt TEXT;
	product_id UUID;
BEGIN
	FOR pt IN SELECT type FROM product_type
	LOOP
		SELECT array_agg(name ORDER BY name) INTO config_names FROM product_config pc WHERE product_type = pt;
		FOR product_id IN SELECT id FROM product WHERE product.attribute ->> ''productType'' = pt
		LOOP
			SELECT array_remove(array_agg(json_keys ORDER BY json_keys), ''productType'') INTO product_config_names FROM (
				SELECT jsonb_object_keys(attribute) json_keys, id FROM product p
				WHERE p.id = product_id
			) a GROUP BY a.id;
			ASSERT config_names @> product_config_names,
				format(''config names of product [%s] is invalid, allowed configs: %s, configs in product: %s'', product_id, config_names, product_config_names);
		END LOOP;
	END LOOP;
END ';

-- Assert values in 'attribute' jsonb column of table 'product' are all in 'product_config_value' table
DO '
DECLARE
	config_values TEXT[];
	product_config_values TEXT[];
	pt TEXT;
	config_name TEXT;
	product_id UUID;
	attr_exist BOOL;
BEGIN
	FOR pt IN SELECT type FROM product_type
	LOOP
		FOR config_name IN SELECT name FROM product_config pc WHERE product_type = pt
		LOOP
			SELECT array_agg(value ORDER BY value) INTO config_values
				FROM product_config_value pcv JOIN product_config pc ON pcv.product_config_id = pc.id
				WHERE pc.product_type = pt AND pc.name = config_name;
			FOR product_id IN SELECT id FROM product WHERE product.attribute ->> ''productType'' = pt
			LOOP
				SELECT jsonb_path_exists(attribute, format(''$.%s'', config_name)::JSONPATH) INTO attr_exist FROM product p WHERE p.id = product_id;
				IF attr_exist IS TRUE THEN
					SELECT array_agg(json_values) INTO product_config_values FROM (
						SELECT jsonb_array_elements_text(jsonb_path_query_array(attribute, format(''$.%s'', config_name)::JSONPATH)) json_values, id FROM product p
						WHERE p.id = product_id
					) a GROUP BY a.id;
					ASSERT config_values @> product_config_values,
						format(''config values of [%s] of product [%s] is invalid, allowed values: %s, values in product: %s'', config_name, product_id, config_values, product_config_values);
				END IF;
			END LOOP;
		END LOOP;
	END LOOP;
END ';

COMMIT;
