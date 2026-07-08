-- D1: AMAZON RDS (Credit DB) - Zona BD Restringida
CREATE TABLE IF NOT EXISTS credits (
    id SERIAL PRIMARY KEY,
    dni VARCHAR(20) NOT NULL,
    nombre VARCHAR(150) NOT NULL,
    monto NUMERIC(12,2) NOT NULL,
    estado VARCHAR(20) NOT NULL DEFAULT 'PENDIENTE',
    created_at TIMESTAMP DEFAULT NOW()
);

-- Datos semilla para las pruebas de The Break / The Repair
INSERT INTO credits (dni, nombre, monto, estado) VALUES
('45678912', 'Ana Quispe', 1000.00, 'APROBADO'),
('11223344', 'Luis Mamani', 2500.00, 'APROBADO'),
('99887766', 'Rosa Torres', 800.00, 'PENDIENTE')
ON CONFLICT DO NOTHING;
