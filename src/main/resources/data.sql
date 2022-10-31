-- Init table index(json field)
CREATE INDEX IF NOT EXISTS external_purl_ref_purl_idx ON external_purl_ref USING btree (jsonb_extract_path_text ( purl,'type'), jsonb_extract_path_text ( purl,'name'));

-- Init table product_type
INSERT INTO product_type VALUES('openEuler')
ON CONFLICT (type) DO NOTHING;

INSERT INTO product_type VALUES('MindSpore')
ON CONFLICT (type) DO NOTHING;

INSERT INTO product_type VALUES('openGauss')
ON CONFLICT (type) DO NOTHING;

-- Init table product_config

--openEuler
INSERT INTO product_config(id, name, label, value_type, ord, product_type)
VALUES('013d61a1-5938-46db-9092-88df47c10bf6', 'version', '版本号', 'enum([{"label":"openEuler-22.03-LTS","value":"openEuler-22.03-LTS"},{"label":"openEuler-20.03-LTS-SP3","value":"openEuler-20.03-LTS-SP3"},{"label":"openEuler-20.03-LTS-SP2","value":"openEuler-20.03-LTS-SP2"},{"label":"openEuler-20.03-LTS-SP1","value":"openEuler-20.03-LTS-SP1"}])', 1, 'openEuler')
ON CONFLICT (id) DO UPDATE
    SET name = EXCLUDED.name, label = EXCLUDED.label, value_type = EXCLUDED.value_type, ord = EXCLUDED.ord, product_type = EXCLUDED.product_type;

INSERT INTO product_config(id, name, label, value_type, ord, product_type)
VALUES('f0266c11-1d7a-45c6-80e6-2ccf586f6755', 'imageFormat', '文件格式', 'enum([{"label":"ISO","value":"ISO"},{"label":"EPOL","value":"EPOL"}])', 2, 'openEuler')
ON CONFLICT (id) DO UPDATE
    SET name = EXCLUDED.name, label = EXCLUDED.label, value_type = EXCLUDED.value_type, ord = EXCLUDED.ord, product_type = EXCLUDED.product_type;

INSERT INTO product_config(id, name, label, value_type, ord, product_type)
VALUES('7f959c6b-6651-4c56-be30-5e2cebb901cf', 'imageType', '镜像类型', 'enum([{"label":"Everything","value":"everything"},{"label":"Normal","value":"empty"},{"label":"Update","value":"update"},{"label":"Update Train","value":"update-train"},{"label":"Update Wallaby","value":"update-wallaby"}])', 3, 'openEuler')
ON CONFLICT (id) DO UPDATE
    SET name = EXCLUDED.name, label = EXCLUDED.label, value_type = EXCLUDED.value_type, ord = EXCLUDED.ord, product_type = EXCLUDED.product_type;

INSERT INTO product_config(id, name, label, value_type, ord, product_type)
VALUES('5263c064-4d04-4232-a717-eb84499b5f5f', 'arch', '系统架构', 'enum([{"label":"aarch64","value":"aarch64"},{"label":"x86_64","value":"x86_64"}])', 4, 'openEuler')
ON CONFLICT (id) DO UPDATE
    SET name = EXCLUDED.name, label = EXCLUDED.label, value_type = EXCLUDED.value_type, ord = EXCLUDED.ord, product_type = EXCLUDED.product_type;


-- MindSpore
INSERT INTO product_config(id, name, label, value_type, ord, product_type)
VALUES('d96a0380-d9c0-4176-bbd6-9578952636f6', 'version', '版本号', 'enum([{"label":"1.8.0","value":"1.8.0"}])', 1, 'MindSpore')
ON CONFLICT (id) DO UPDATE
    SET name = EXCLUDED.name, label = EXCLUDED.label, value_type = EXCLUDED.value_type, ord = EXCLUDED.ord, product_type = EXCLUDED.product_type;

INSERT INTO product_config(id, name, label, value_type, ord, product_type)
VALUES('a4e710c7-6811-4626-b32b-ae067fade540', 'platform', '硬件平台', 'enum([{"label":"CPU","value":"CPU"}])', 2, 'MindSpore')
ON CONFLICT (id) DO UPDATE
    SET name = EXCLUDED.name, label = EXCLUDED.label, value_type = EXCLUDED.value_type, ord = EXCLUDED.ord, product_type = EXCLUDED.product_type;

INSERT INTO product_config(id, name, label, value_type, ord, product_type)
VALUES('327af62f-9689-4dd4-a1ff-b8ff7ad0bd61', 'os', '操作系统', 'enum([{"label":"Linux","value":"Linux"}])', 3, 'MindSpore')
ON CONFLICT (id) DO UPDATE
    SET name = EXCLUDED.name, label = EXCLUDED.label, value_type = EXCLUDED.value_type, ord = EXCLUDED.ord, product_type = EXCLUDED.product_type;

INSERT INTO product_config(id, name, label, value_type, ord, product_type)
VALUES('75e5459b-b969-49e7-9d68-f2f346eb2120', 'arch', '系统架构', 'enum([{"label":"aarch64","value":"aarch64"},{"label":"x86_64","value":"x86_64"}])', 4, 'MindSpore')
ON CONFLICT (id) DO UPDATE
    SET name = EXCLUDED.name, label = EXCLUDED.label, value_type = EXCLUDED.value_type, ord = EXCLUDED.ord, product_type = EXCLUDED.product_type;

INSERT INTO product_config(id, name, label, value_type, ord, product_type)
VALUES('e471690e-69a1-4646-8868-036e53d702c6', 'language', '编程语言', 'enum([{"label":"Python 3.7.0","value":"Python 3.7.0"},{"label":"Python 3.8.0","value":"Python 3.8.0"},{"label":"Python 3.9.0","value":"Python 3.9.0"}])', 5, 'MindSpore')
ON CONFLICT (id) DO UPDATE
    SET name = EXCLUDED.name, label = EXCLUDED.label, value_type = EXCLUDED.value_type, ord = EXCLUDED.ord, product_type = EXCLUDED.product_type;

-- openGauss
INSERT INTO product_config(id, name, label, value_type, ord, product_type)
VALUES('527a8727-2d7e-4db4-b138-acb33405e447', 'version', '版本号', 'enum([{"label":"3.1.0","value":"3.1.0"}])', 1, 'openGauss')
ON CONFLICT (id) DO UPDATE
    SET name = EXCLUDED.name, label = EXCLUDED.label, value_type = EXCLUDED.value_type, ord = EXCLUDED.ord, product_type = EXCLUDED.product_type;

INSERT INTO product_config(id, name, label, value_type, ord, product_type)
VALUES('243452d3-da07-4fab-ad74-8767629528fa', 'os', '操作系统', 'enum([{"label":"CentOS","value":"CentOS"}, {"label":"openEuler","value":"openEuler"}])', 2, 'openGauss')
ON CONFLICT (id) DO UPDATE
    SET name = EXCLUDED.name, label = EXCLUDED.label, value_type = EXCLUDED.value_type, ord = EXCLUDED.ord, product_type = EXCLUDED.product_type;

INSERT INTO product_config(id, name, label, value_type, ord, product_type)
VALUES('c589facd-4ac6-441d-b8fa-a787ea60c18e', 'arch', '系统架构', 'enum([{"label":"aarch64","value":"aarch64"},{"label":"x86_64","value":"x86_64"}])', 3, 'openGauss')
ON CONFLICT (id) DO UPDATE
    SET name = EXCLUDED.name, label = EXCLUDED.label, value_type = EXCLUDED.value_type, ord = EXCLUDED.ord, product_type = EXCLUDED.product_type;

-- Insert openEuler products
INSERT INTO product(id, name, attribute)
VALUES('4a34d4b7-25ce-4c8d-b2f7-9d210a6dd32c', 'openEuler-22.03-LTS-x86_64-dvd.iso', '{"productType":"openEuler", "version":"openEuler-22.03-LTS","imageFormat":"ISO","imageType":"empty","arch":"x86_64"}'::jsonb)
ON CONFLICT (id) DO UPDATE
    SET name = EXCLUDED.name, attribute = EXCLUDED.attribute;

INSERT INTO product(id, name, attribute)
VALUES('55dfefff-ec35-49f4-b395-de3824605bbc', 'openEuler-22.03-LTS-everything-x86_64-dvd.iso', '{"productType":"openEuler", "version":"openEuler-22.03-LTS","imageFormat":"ISO","imageType":"everything","arch":"x86_64"}'::jsonb)
ON CONFLICT (id) DO UPDATE
    SET name = EXCLUDED.name, attribute = EXCLUDED.attribute;

INSERT INTO product(id, name, attribute)
VALUES('a51b9584-e7af-47cb-9f96-fa112e234648', '/openEuler-22.03-LTS/update/x86_64', '{"productType":"openEuler", "version":"openEuler-22.03-LTS","imageFormat":"ISO","imageType":"update","arch":"x86_64"}'::jsonb)
ON CONFLICT (id) DO UPDATE
    SET name = EXCLUDED.name, attribute = EXCLUDED.attribute;

INSERT INTO product(id, name, attribute)
VALUES('7b114872-0518-436f-bf23-c21d5eaf3bbb', 'openEuler-22.03-LTS-aarch64-dvd.iso', '{"productType":"openEuler", "version":"openEuler-22.03-LTS","imageFormat":"ISO","imageType":"empty","arch":"aarch64"}'::jsonb)
ON CONFLICT (id) DO UPDATE
    SET name = EXCLUDED.name, attribute = EXCLUDED.attribute;

INSERT INTO product(id, name, attribute)
VALUES('96d17128-644e-4019-bff1-40516d97ab31', 'openEuler-22.03-LTS-everything-aarch64-dvd.iso', '{"productType":"openEuler", "version":"openEuler-22.03-LTS","imageFormat":"ISO","imageType":"everything","arch":"aarch64"}'::jsonb)
ON CONFLICT (id) DO UPDATE
    SET name = EXCLUDED.name, attribute = EXCLUDED.attribute;

INSERT INTO product(id, name, attribute)
VALUES('7f1cd2d8-f81f-4816-854d-20f2d85348eb', '/openEuler-22.03-LTS/update/aarch64', '{"productType":"openEuler", "version":"openEuler-22.03-LTS","imageFormat":"ISO","imageType":"update","arch":"aarch64"}'::jsonb)
ON CONFLICT (id) DO UPDATE
    SET name = EXCLUDED.name, attribute = EXCLUDED.attribute;

INSERT INTO product(id, name, attribute)
VALUES('f71b86c2-3d0c-4e9a-a9eb-b1bad0213d02', '/openEuler-22.03-LTS/EPOL/update/multi_version/OpenStack/Wallaby/aarch64', '{"productType":"openEuler", "version":"openEuler-22.03-LTS","imageFormat":"EPOL","imageType":"update-wallaby","arch":"aarch64"}'::jsonb)
ON CONFLICT (id) DO UPDATE
    SET name = EXCLUDED.name, attribute = EXCLUDED.attribute;

INSERT INTO product(id, name, attribute)
VALUES('d8c855f8-6df0-4149-8b29-155e1714c6a7', '/openEuler-22.03-LTS/EPOL/update/multi_version/OpenStack/Wallaby/x86_64', '{"productType":"openEuler", "version":"openEuler-22.03-LTS","imageFormat":"EPOL","imageType":"update-wallaby","arch":"x86_64"}'::jsonb)
ON CONFLICT (id) DO UPDATE
    SET name = EXCLUDED.name, attribute = EXCLUDED.attribute;

INSERT INTO product(id, name, attribute)
VALUES('c4599563-e78a-488e-8cb7-5ff53ebf5eb7', '/openEuler-22.03-LTS/EPOL/update/multi_version/OpenStack/Train/aarch64', '{"productType":"openEuler", "version":"openEuler-22.03-LTS","imageFormat":"EPOL","imageType":"update-train","arch":"aarch64"}'::jsonb)
ON CONFLICT (id) DO UPDATE
    SET name = EXCLUDED.name, attribute = EXCLUDED.attribute;

INSERT INTO product(id, name, attribute)
VALUES('ae7201b8-8548-463b-ac2e-b8a6cd6610da', '/openEuler-22.03-LTS/EPOL/update/multi_version/OpenStack/Train/x86_64', '{"productType":"openEuler", "version":"openEuler-22.03-LTS","imageFormat":"EPOL","imageType":"update-train","arch":"x86_64"}'::jsonb)
ON CONFLICT (id) DO UPDATE
    SET name = EXCLUDED.name, attribute = EXCLUDED.attribute;

INSERT INTO product(id, name, attribute)
VALUES('9bdab31c-a7bd-4383-b0c5-16d28e148e43', '/openEuler-20.03-LTS-SP3/update/aarch64', '{"productType":"openEuler", "version":"openEuler-20.03-LTS-SP3","imageFormat":"ISO","imageType":"update","arch":"aarch64"}'::jsonb)
ON CONFLICT (id) DO UPDATE
    SET name = EXCLUDED.name, attribute = EXCLUDED.attribute;

INSERT INTO product(id, name, attribute)
VALUES('27516015-2c95-4f1e-ada9-926dc3ffad03', '/openEuler-20.03-LTS-SP3/update/x86_64', '{"productType":"openEuler", "version":"openEuler-20.03-LTS-SP3","imageFormat":"ISO","imageType":"update","arch":"x86_64"}'::jsonb)
ON CONFLICT (id) DO UPDATE
    SET name = EXCLUDED.name, attribute = EXCLUDED.attribute;

INSERT INTO product(id, name, attribute)
VALUES('797d8d29-7cab-4468-ba02-7e0078fee5a5', '/openEuler-20.03-LTS-SP3/EPOL/update/main/aarch64', '{"productType":"openEuler", "version":"openEuler-20.03-LTS-SP3","imageFormat":"EPOL","imageType":"update","arch":"aarch64"}'::jsonb)
ON CONFLICT (id) DO UPDATE
    SET name = EXCLUDED.name, attribute = EXCLUDED.attribute;

INSERT INTO product(id, name, attribute)
VALUES('55540832-de6c-49c0-b3f2-b4b62e8569ad', '/openEuler-20.03-LTS-SP3/EPOL/update/main/x86_64', '{"productType":"openEuler", "version":"openEuler-20.03-LTS-SP3","imageFormat":"EPOL","imageType":"update","arch":"x86_64"}'::jsonb)
ON CONFLICT (id) DO UPDATE
    SET name = EXCLUDED.name, attribute = EXCLUDED.attribute;

INSERT INTO product(id, name, attribute)
VALUES('ae9f6ef1-66c8-44dd-965e-2471d52da765', '/openEuler-20.03-LTS-SP2/update/aarch64', '{"productType":"openEuler", "version":"openEuler-20.03-LTS-SP2","imageFormat":"ISO","imageType":"update","arch":"aarch64"}'::jsonb)
ON CONFLICT (id) DO UPDATE
    SET name = EXCLUDED.name, attribute = EXCLUDED.attribute;

INSERT INTO product(id, name, attribute)
VALUES('a9f04d75-433e-476d-b1c7-6a64a7feb8c3', '/openEuler-20.03-LTS-SP2/update/x86_64', '{"productType":"openEuler", "version":"openEuler-20.03-LTS-SP2","imageFormat":"ISO","imageType":"update","arch":"x86_64"}'::jsonb)
ON CONFLICT (id) DO UPDATE
    SET name = EXCLUDED.name, attribute = EXCLUDED.attribute;

INSERT INTO product(id, name, attribute)
VALUES('2adb6add-d69b-4f29-9233-86c29a205250', '/openEuler-20.03-LTS-SP2/EPOL/update/main/aarch64', '{"productType":"openEuler", "version":"openEuler-20.03-LTS-SP2","imageFormat":"EPOL","imageType":"update","arch":"aarch64"}'::jsonb)
ON CONFLICT (id) DO UPDATE
    SET name = EXCLUDED.name, attribute = EXCLUDED.attribute;

INSERT INTO product(id, name, attribute)
VALUES('93887c35-5a21-4d6a-bf9f-8158a17adcb3', '/openEuler-20.03-LTS-SP2/EPOL/update/main/x86_64', '{"productType":"openEuler", "version":"openEuler-20.03-LTS-SP2","imageFormat":"EPOL","imageType":"update","arch":"x86_64"}'::jsonb)
ON CONFLICT (id) DO UPDATE
    SET name = EXCLUDED.name, attribute = EXCLUDED.attribute;

INSERT INTO product(id, name, attribute)
VALUES('d22c6135-1506-4c29-bbc3-167f94fdb38d', '/openEuler-20.03-LTS-SP1/update/aarch64', '{"productType":"openEuler", "version":"openEuler-20.03-LTS-SP1","imageFormat":"ISO","imageType":"update","arch":"aarch64"}'::jsonb)
ON CONFLICT (id) DO UPDATE
    SET name = EXCLUDED.name, attribute = EXCLUDED.attribute;

INSERT INTO product(id, name, attribute)
VALUES('b127e9ad-42ca-46c5-8777-9cd946de0e0a', '/openEuler-20.03-LTS-SP1/update/x86_64', '{"productType":"openEuler", "version":"openEuler-20.03-LTS-SP1","imageFormat":"ISO","imageType":"update","arch":"x86_64"}'::jsonb)
ON CONFLICT (id) DO UPDATE
    SET name = EXCLUDED.name, attribute = EXCLUDED.attribute;

INSERT INTO product(id, name, attribute)
VALUES('e50d0398-2516-4ab4-88d6-9199662a710a', '/openEuler-20.03-LTS-SP1/EPOL/update/aarch64', '{"productType":"openEuler", "version":"openEuler-20.03-LTS-SP1","imageFormat":"EPOL ","imageType":"update","arch":"aarch64"}'::jsonb)
ON CONFLICT (id) DO UPDATE
    SET name = EXCLUDED.name, attribute = EXCLUDED.attribute;

INSERT INTO product(id, name, attribute)
VALUES('ae05237c-9d45-4fe0-afe3-a5fbf7004686', '/openEuler-20.03-LTS-SP1/EPOL/update/x86_64', '{"productType":"openEuler", "version":"openEuler-20.03-LTS-SP1","imageFormat":"EPOL","imageType":"update","arch":"x86_64"}'::jsonb)
ON CONFLICT (id) DO UPDATE
    SET name = EXCLUDED.name, attribute = EXCLUDED.attribute;

-- Insert MindSpore products
INSERT INTO product(id, name, attribute)
VALUES('e686d5ba-cd30-41e7-b97a-a3481bb6e0a2', 'mindspore-1.8.0-cp37-cp37m-linux_x86_64.whl', '{"productType": "MindSpore", "version": "1.8.0","platform": "CPU", "os": "Linux", "arch": "x86_64", "language": "Python 3.7.0"}'::jsonb)
ON CONFLICT (id) DO UPDATE
    SET name = EXCLUDED.name, attribute = EXCLUDED.attribute;

-- Insert openGauss products
INSERT INTO product(id, name, attribute)
VALUES('6c1bca0c-b8f2-40f5-90fe-75a376430748', 'openGauss-3.1.0-CentOS-64bit', '{"productType": "openGauss", "version": "3.1.0", "os": "CentOS", "arch": "x86_64"}'::jsonb)
ON CONFLICT (id) DO UPDATE
    SET name = EXCLUDED.name, attribute = EXCLUDED.attribute;
