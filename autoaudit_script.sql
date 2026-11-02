-- ============================================================================
-- PROYECTO AUTOAUDIT - SISTEMA DE AUDITORÍA AUTOMATIZADO
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. ESTRUCTURAS DE CONFIGURACIÓN Y BITÁCORA (DDL)
-- ----------------------------------------------------------------------------

DROP TABLE IF EXISTS bitacora_cambios CASCADE;
DROP TABLE IF EXISTS config_columnas CASCADE;
DROP TABLE IF EXISTS config_tablas CASCADE;
DROP TABLE IF EXISTS empleados CASCADE;

-- Tabla de configuración por tabla
CREATE TABLE config_tablas (
    id_tabla SERIAL PRIMARY KEY,
    nombre_tabla VARCHAR(100) NOT NULL UNIQUE,
    audit_insert BOOLEAN DEFAULT TRUE,
    audit_update BOOLEAN DEFAULT TRUE,
    audit_delete BOOLEAN DEFAULT TRUE,
    activo BOOLEAN DEFAULT TRUE,
    fecha_configuracion TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabla de configuración granular por columna
CREATE TABLE config_columnas (
    id_columna SERIAL PRIMARY KEY,
    id_tabla INT REFERENCES config_tablas(id_tabla) ON DELETE CASCADE,
    nombre_columna VARCHAR(100) NOT NULL,
    auditada BOOLEAN DEFAULT TRUE,
    CONSTRAINT uk_tabla_columna UNIQUE(id_tabla, nombre_columna)
);

-- Tabla centralizada de bitácora
CREATE TABLE bitacora_cambios (
    id_bitacora BIGSERIAL PRIMARY KEY,
    id_configuracion INT REFERENCES config_tablas(id_tabla) ON DELETE SET NULL,
    nombre_tabla VARCHAR(100) NOT NULL,
    nombre_columna VARCHAR(100),
    operacion VARCHAR(10) NOT NULL, -- INSERT, UPDATE, DELETE
    valor_anterior TEXT,
    valor_nuevo TEXT,
    usuario_db VARCHAR(100) NOT NULL,
    estacion_ip VARCHAR(45),
    fecha_hora TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);


-- ----------------------------------------------------------------------------
-- 2. CONSULTAS AL DICCIONARIO DE DATOS
-- ----------------------------------------------------------------------------

CREATE OR REPLACE VIEW vista_diccionario_tablas AS
SELECT table_name 
FROM information_schema.tables 
WHERE table_schema = 'public' 
  AND table_type = 'BASE TABLE'
  AND table_name NOT IN ('config_tablas', 'config_columnas', 'bitacora_cambios');

CREATE OR REPLACE VIEW vista_diccionario_columnas AS
SELECT table_name, column_name, data_type 
FROM information_schema.columns 
WHERE table_schema = 'public' 
  AND table_name NOT IN ('config_tablas', 'config_columnas', 'bitacora_cambios');


-- ----------------------------------------------------------------------------
-- 3. GENERACIÓN DINÁMICA DE TRIGGERS Y FUNCIÓN RECEPTORA
-- ----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION fn_procesar_auditoria()
RETURNS TRIGGER AS $$
DECLARE
    r_tabla RECORD;
    r_col RECORD;
    val_old TEXT;
    val_new TEXT;
    ip_origen VARCHAR(45);
    ip_inet INET;
BEGIN
    ip_inet := inet_client_addr();
    IF ip_inet IS NULL THEN
        ip_origen := '127.0.0.1 (Localhost)';
    ELSE
        ip_origen := host(ip_inet);
    END IF;

    SELECT * INTO r_tabla 
    FROM config_tablas 
    WHERE nombre_tabla = TG_TABLE_NAME AND activo = TRUE;

    IF NOT FOUND THEN
        RETURN NULL;
    END IF;

    IF (TG_OP = 'INSERT') THEN
        IF r_tabla.audit_insert THEN
            FOR r_col IN 
                SELECT nombre_columna 
                FROM config_columnas 
                WHERE id_tabla = r_tabla.id_tabla AND auditada = TRUE
            LOOP
                EXECUTE format('SELECT ($1).%I::text', r_col.nombre_columna) INTO val_new USING NEW;
                
                INSERT INTO bitacora_cambios(
                    id_configuracion, nombre_tabla, nombre_columna, operacion, 
                    valor_anterior, valor_nuevo, usuario_db, estacion_ip
                ) VALUES (
                    r_tabla.id_tabla, TG_TABLE_NAME, r_col.nombre_columna, 'INSERT',
                    NULL, val_new, session_user, ip_origen
                );
            END LOOP;
        END IF;
        RETURN NEW;

    ELSIF (TG_OP = 'UPDATE') THEN
        IF r_tabla.audit_update THEN
            FOR r_col IN 
                SELECT nombre_columna 
                FROM config_columnas 
                WHERE id_tabla = r_tabla.id_tabla AND auditada = TRUE
            LOOP
                EXECUTE format('SELECT ($1).%I::text', r_col.nombre_columna) INTO val_old USING OLD;
                EXECUTE format('SELECT ($1).%I::text', r_col.nombre_columna) INTO val_new USING NEW;

                IF val_old IS DISTINCT FROM val_new THEN
                    INSERT INTO bitacora_cambios(
                        id_configuracion, nombre_tabla, nombre_columna, operacion, 
                        valor_anterior, valor_nuevo, usuario_db, estacion_ip
                    ) VALUES (
                        r_tabla.id_tabla, TG_TABLE_NAME, r_col.nombre_columna, 'UPDATE',
                        val_old, val_new, session_user, ip_origen
                    );
                END IF;
            END LOOP;
        END IF;
        RETURN NEW;

    ELSIF (TG_OP = 'DELETE') THEN
        IF r_tabla.audit_delete THEN
            FOR r_col IN 
                SELECT nombre_columna 
                FROM config_columnas 
                WHERE id_tabla = r_tabla.id_tabla AND auditada = TRUE
            LOOP
                EXECUTE format('SELECT ($1).%I::text', r_col.nombre_columna) INTO val_old USING OLD;

                INSERT INTO bitacora_cambios(
                    id_configuracion, nombre_tabla, nombre_columna, operacion, 
                    valor_anterior, valor_nuevo, usuario_db, estacion_ip
                ) VALUES (
                    r_tabla.id_tabla, TG_TABLE_NAME, r_col.nombre_columna, 'DELETE',
                    val_old, NULL, session_user, ip_origen
                );
            END LOOP;
        END IF;
        RETURN OLD;
    END IF;

    RETURN NULL;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;


CREATE OR REPLACE PROCEDURE sp_generar_trigger_auditoria(p_nombre_tabla VARCHAR)
LANGUAGE plpgsql AS $$
DECLARE
    v_sql TEXT;
    v_trigger_name TEXT;
    v_eventos TEXT := '';
    r_config RECORD;
BEGIN
    SELECT * INTO r_config FROM config_tablas WHERE nombre_tabla = p_nombre_tabla AND activo = TRUE;
    
    v_trigger_name := 'trg_audit_' || p_nombre_tabla;

    EXECUTE format('DROP TRIGGER IF EXISTS %I ON %I;', v_trigger_name, p_nombre_tabla);

    IF r_config IS NULL THEN
        RAISE NOTICE 'La tabla % no posee una configuración activa.', p_nombre_tabla;
        RETURN;
    END IF;

    IF r_config.audit_insert THEN v_eventos := v_eventos || 'INSERT OR '; END IF;
    IF r_config.audit_update THEN v_eventos := v_eventos || 'UPDATE OR '; END IF;
    IF r_config.audit_delete THEN v_eventos := v_eventos || 'DELETE OR '; END IF;

    IF v_eventos = '' THEN
        RAISE NOTICE 'No hay eventos configurados para %.', p_nombre_tabla;
        RETURN;
    END IF;

    v_eventos := RTRIM(v_eventos, 'OR ');

    v_sql := format(
        'CREATE TRIGGER %I AFTER %s ON %I FOR EACH ROW EXECUTE FUNCTION fn_procesar_auditoria();',
        v_trigger_name,
        v_eventos,
        p_nombre_tabla
    );

    EXECUTE v_sql;
    RAISE NOTICE 'Trigger % creado dinámicamente.', v_trigger_name;
END;
$$;


-- ----------------------------------------------------------------------------
-- 4. CONSULTAS HISTÓRICAS Y REPORTES
-- ----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION fn_reporte_por_usuario(p_usuario VARCHAR)
RETURNS TABLE (
    id_bitacora BIGINT,
    nombre_tabla VARCHAR,
    nombre_columna VARCHAR,
    operacion VARCHAR,
    valor_anterior TEXT,
    valor_nuevo TEXT,
    estacion_ip VARCHAR,
    fecha_hora TIMESTAMP
) AS $$
BEGIN
    RETURN QUERY
    SELECT b.id_bitacora, b.nombre_tabla, b.nombre_columna, b.operacion, 
           b.valor_anterior, b.valor_nuevo, b.estacion_ip, b.fecha_hora
    FROM bitacora_cambios b
    WHERE b.usuario_db = p_usuario
    ORDER BY b.fecha_hora DESC;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION fn_reporte_por_columna(p_tabla VARCHAR, p_columna VARCHAR)
RETURNS TABLE (
    id_bitacora BIGINT,
    operacion VARCHAR,
    valor_anterior TEXT,
    valor_nuevo TEXT,
    usuario_db VARCHAR,
    estacion_ip VARCHAR,
    fecha_hora TIMESTAMP
) AS $$
BEGIN
    RETURN QUERY
    SELECT b.id_bitacora, b.operacion, b.valor_anterior, b.valor_nuevo, 
           b.usuario_db, b.estacion_ip, b.fecha_hora
    FROM bitacora_cambios b
    WHERE b.nombre_tabla = p_tabla AND b.nombre_columna = p_columna
    ORDER BY b.fecha_hora DESC;
END;
$$ LANGUAGE plpgsql;


-- ----------------------------------------------------------------------------
-- 5. CONFIGURACIÓN Y DATOS DE PRUEBA PERMANENTES
-- ----------------------------------------------------------------------------

-- Crear tabla de prueba
CREATE TABLE empleados (
    id_empleado SERIAL PRIMARY KEY,
    nombre VARCHAR(100),
    puesto VARCHAR(100),
    salario NUMERIC(10,2)
);

-- Configurar auditoría
INSERT INTO config_tablas (nombre_tabla, audit_insert, audit_update, audit_delete) 
VALUES ('empleados', TRUE, TRUE, TRUE);

INSERT INTO config_columnas (id_tabla, nombre_columna) 
VALUES 
((SELECT id_tabla FROM config_tablas WHERE nombre_tabla = 'empleados'), 'nombre'),
((SELECT id_tabla FROM config_tablas WHERE nombre_tabla = 'empleados'), 'salario');

-- Generar el trigger dinámico
CALL sp_generar_trigger_auditoria('empleados');

-- Inserción y actualización para generar registros en bitácora
INSERT INTO empleados (nombre, puesto, salario) VALUES ('Carlos Gómez', 'Analista BD', 5000.00);
UPDATE empleados SET salario = 5500.00 WHERE id_empleado = 1;

-- Consultas de verificación
SELECT * FROM bitacora_cambios;
SELECT * FROM fn_reporte_por_usuario(session_user::varchar);
SELECT * FROM fn_reporte_por_columna('empleados', 'salario');