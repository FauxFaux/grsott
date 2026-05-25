pub struct Field {
    pub name: &'static str,
    pub off: u16,
    pub kind: FieldKind,
    pub useful: bool,
}

pub enum FieldKind {
    U32 { divide: f64 },
    I32 { divide: f64 },
    I16 { divide: f64 },
    U16 { divide: f64 },
}

impl Field {
    pub fn read_value(&self, body: &[u8]) -> Option<f64> {
        let off = usize::from(self.off);
        let len = usize::from(self.kind.len());

        if body.len() < off + len {
            return None;
        }

        let slice = &body[off..off + len];
        let raw = match self.kind {
            FieldKind::U32 { .. } => f64::from(u32::from_be_bytes(slice.try_into().ok()?)),
            FieldKind::I32 { .. } => f64::from(i32::from_be_bytes(slice.try_into().ok()?)),
            FieldKind::U16 { .. } => f64::from(u16::from_be_bytes(slice.try_into().ok()?)),
            FieldKind::I16 { .. } => f64::from(i16::from_be_bytes(slice.try_into().ok()?)),
        };

        let divide = self.kind.divide()?;
        Some(f64::from(raw) / f64::from(divide))
    }
}

impl FieldKind {
    pub fn divide(&self) -> Option<f64> {
        match self {
            FieldKind::U32 { divide } => Some(*divide),
            FieldKind::I32 { divide } => Some(*divide),
            FieldKind::U16 { divide } => Some(*divide),
            FieldKind::I16 { divide } => Some(*divide),
        }
    }

    pub fn len(&self) -> u16 {
        match self {
            FieldKind::U32 { .. } => u32::BITS as u16 / 8,
            FieldKind::I32 { .. } => i32::BITS as u16 / 8,
            FieldKind::U16 { .. } => u16::BITS as u16 / 8,
            FieldKind::I16 { .. } => i16::BITS as u16 / 8,
        }
    }
}

pub fn pkt_51_20() -> Vec<Field> {
    vec![
        u4("vac1", 60 + 3 * 4, 10, true),
        u4("vac2", 60 + 4 * 4, 10, false),
        u4("vac3", 60 + 5 * 4, 10, false),
        u4("current_l1", 60 + 6 * 4, 10, true),
        u4("current_l2", 60 + 7 * 4, 10, false),
        u4("current_l3", 60 + 8 * 4, 10, false),
        i4("act_power_l1", 60 + 9 * 4, 10, true),
        i4("act_power_l2", 60 + 10 * 4, 10, false),
        i4("act_power_l3", 60 + 11 * 4, 10, false),
        i4("app_power_l1", 60 + 12 * 4, 10, true),
        i4("app_power_l2", 60 + 13 * 4, 10, false),
        i4("app_power_l3", 60 + 14 * 4, 10, false),
        i4("react_power_l1", 60 + 15 * 4, 10, true),
        i4("react_power_l2", 60 + 16 * 4, 10, false),
        i4("react_power_l3", 60 + 17 * 4, 10, false),
        i4("powerfactor_l1", 60 + 18 * 4, 1000, true),
        i4("powerfactor_l2", 60 + 19 * 4, 1000, false),
        i4("powerfactor_l3", 60 + 20 * 4, 1000, false),
        i4("pos_rev_act_power", 60 + 21 * 4, 10, true),
        i4("app_power", 60 + 22 * 4, 10, true),
        i4("react_power", 60 + 23 * 4, 10, true),
        i4("powerfactor", 60 + 24 * 4, 1000, true),
        u4("frequency", 60 + 25 * 4, 10, false),
        u4("L1-2_voltage", 60 + 26 * 4, 10, false),
        u4("L2-3_voltage", 60 + 27 * 4, 10, false),
        u4("L3-1_voltage", 60 + 28 * 4, 10, false),
        i4("etoUserTotal", 60 + 29 * 4, 10, true),
        i4("etogridTotal", 60 + 30 * 4, 10, true),
        i4("pos_act_energy_kvar", 60 + 31 * 4, 10, false),
        i4("rev_act_energy_kvar", 60 + 32 * 4, 10, false),
        i4("app_energy_kvar", 60 + 33 * 4, 10, false),
        i4("act_energy_kwh", 60 + 34 * 4, 10, true),
        i4("react_energy_kvar", 60 + 35 * 4, 10, false),
    ]
}

pub fn pkt_51_04() -> Vec<Field> {
    vec![
        u2("status", 71, 1, true),
        u4("ppv", 73, 10, true),
        u2("vpv1", 77, 10, true),
        u2("ipv1", 79, 10, true),
        u4("ppv1", 81, 10, true),
        u2("vpv2", 85, 10, true),
        u2("ipv2", 87, 10, true),
        u4("ppv2", 89, 10, true),
        u4("pac", 141, 10, true),
        u2("fac", 145, 100, true),
        u2("vac1", 147, 10, true),
        u4("pac1", 151, 10, false),
        u4("eacToday", 177, 10, true),
        u4("eacTotal", 181, 10, true),
        u4("pdischarge1", 343, 10, true),
        u4("pcharge1", 347, 10, true),
        u2("vbat", 351, 10, true),
        u2("soc", 353, 1, true),
        u4("pacToUserR", 355, 10, true),
        u4("pacToGridR", 371, 10, true),
    ]
}

fn u4(name: &'static str, off: u16, divide: impl Into<f64>, useful: bool) -> Field {
    Field {
        name,
        off,
        kind: FieldKind::U32 {
            divide: divide.into(),
        },
        useful,
    }
}

fn i4(name: &'static str, off: u16, divide: impl Into<f64>, useful: bool) -> Field {
    Field {
        name,
        off,
        kind: FieldKind::I32 {
            divide: divide.into(),
        },
        useful,
    }
}

fn u2(name: &'static str, off: u16, divide: impl Into<f64>, useful: bool) -> Field {
    Field {
        name,
        off,
        kind: FieldKind::U16 {
            divide: divide.into(),
        },
        useful,
    }
}
