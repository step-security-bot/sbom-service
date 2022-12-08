begin;

-- Configs defined only for tests
INSERT INTO product_type VALUES('testProduct')
ON CONFLICT (type) DO NOTHING;

INSERT INTO product_config(id, name, label, ord, product_type)
VALUES('13565ac5-7f88-437d-a70b-11998e98c088', 'arg', '测试参数', 1, 'testProduct')
ON CONFLICT (id) DO UPDATE
    SET name = EXCLUDED.name, label = EXCLUDED.label, ord = EXCLUDED.ord, product_type = EXCLUDED.product_type;

INSERT INTO product_config_value(id, value, label, product_config_id)
VALUES
('d039235d-4ad9-43f2-b06f-6973942212b1', '1', '1', '13565ac5-7f88-437d-a70b-11998e98c088'),
('d039235d-4ad9-43f2-b06f-6973942212b2', '2', '2', '13565ac5-7f88-437d-a70b-11998e98c088'),
('d039235d-4ad9-43f2-b06f-6973942212b3', '3', '3', '13565ac5-7f88-437d-a70b-11998e98c088'),
('d039235d-4ad9-43f2-b06f-6973942212b4', '4', '4', '13565ac5-7f88-437d-a70b-11998e98c088'),
('d039235d-4ad9-43f2-b06f-6973942212b5', '5', '5', '13565ac5-7f88-437d-a70b-11998e98c088'),
('d039235d-4ad9-43f2-b06f-6973942212b6', '6', '6', '13565ac5-7f88-437d-a70b-11998e98c088'),
('d039235d-4ad9-43f2-b06f-6973942212b7', '7', '7', '13565ac5-7f88-437d-a70b-11998e98c088'),
('d039235d-4ad9-43f2-b06f-6973942212b8', '8', '8', '13565ac5-7f88-437d-a70b-11998e98c088')
ON CONFLICT (id) DO UPDATE
    SET value = EXCLUDED.value, product_config_id = EXCLUDED.product_config_id;

INSERT INTO product(id, name, attribute)
VALUES
('11111111-1111-41e7-b97a-a3481bb6e111', 'mindsporeTest', '{"productType": "testProduct", "arg":"1"}'::jsonb),
('11111111-1111-41e7-b97a-a3481bb6e222', 'SpdxReaderTest', '{"productType": "testProduct", "arg":"2"}'::jsonb),
('11111111-1111-41e7-b97a-a3481bb6e333', 'SpdxWriterTest', '{"productType": "testProduct", "arg":"3"}'::jsonb),
('11111111-1111-41e7-b97a-a3481bb6e444', 'publishTest', '{"productType": "testProduct", "arg":"4"}'::jsonb),
('11111111-1111-41e7-b97a-a3481bb6e555', 'mindsporeTracerTest', '{"productType": "testProduct", "arg":"5"}'::jsonb),
('11111111-1111-41e7-b97a-a3481bb6e666', 'publishServiceTest', '{"productType": "testProduct", "arg":"6"}'::jsonb),
('11111111-1111-41e7-b97a-a3481bb6e777', 'repodataTest', '{"productType":"openEuler", "version":"openEuler-22.03-LTS","imageFormat":"ISO","imageType":"Update Wallaby","arch":"x86_64"}'::jsonb)
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

commit;
