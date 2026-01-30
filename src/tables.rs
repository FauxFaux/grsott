pub struct Field {
    pub name: &'static str,
    pub off: u16,
    pub kind: FieldKind,
    pub useful: bool,
}

pub enum FieldKind {
    Text { len: u16 },
    U16 { divide: u16 },
    I16 { divide: i16 },
}

impl FieldKind {
    pub fn divide(&self) -> Option<i32> {
        match self {
            FieldKind::U16 { divide } => Some(i32::from(*divide)),
            FieldKind::I16 { divide } => Some(i32::from(*divide)),
            FieldKind::Text { .. } => None,
        }
    }
}

pub fn pkt_51_20() -> Vec<Field> {
    vec![
        u("voltage_l1", 3, 10, true),
        u("voltage_l2", 4, 10, false),
        u("voltage_l3", 5, 10, false),
        u("current_l1", 6, 10, true),
        u("current_l2", 7, 10, false),
        u("current_l3", 8, 10, false),
        i("act_power_l1", 9, 10, true),
        i("act_power_l2", 10, 10, false),
        i("act_power_l3", 11, 10, false),
        i("app_power_l1", 12, 10, true),
        i("app_power_l2", 13, 10, false),
        i("app_power_l3", 14, 10, false),
        i("react_power_l1", 15, 10, true),
        i("react_power_l2", 16, 10, false),
        i("react_power_l3", 17, 10, false),
        i("powerfactor_l1", 18, 1000, true),
        i("powerfactor_l2", 19, 1000, false),
        i("powerfactor_l3", 20, 1000, false),
        i("pos_rev_act_power", 21, 10, true),
        i("pos_act_power", 21, 10, false),
        i("rev_act_power", 21, 10, false),
        i("app_power", 22, 10, true),
        i("react_power", 23, 10, true),
        i("powerfactor", 24, 1000, true),
        u("frequency", 25, 10, false),
        u("L1-2_voltage", 26, 10, false),
        u("L2-3_voltage", 27, 10, false),
        u("L3-1_voltage", 28, 10, false),
        i("pos_act_energy", 29, 10, true),
        i("rev_act_energy", 30, 10, true),
        i("pos_act_energy_kvar", 31, 10, false),
        i("rev_act_energy_kvar", 32, 10, false),
        i("app_energy_kvar", 33, 10, false),
        i("act_energy_kwh", 34, 10, true),
        i("react_energy_kvar", 35, 10, false),
    ]
}

fn u(name: &'static str, off: u16, divide: u16, useful: bool) -> Field {
    Field {
        name,
        off,
        kind: FieldKind::U16 { divide },
        useful,
    }
}

fn i(name: &'static str, off: u16, divide: i16, useful: bool) -> Field {
    Field {
        name,
        off,
        kind: FieldKind::I16 { divide },
        useful,
    }
}

fn t(name: &'static str, off: u16, len: u16, useful: bool) -> Field {
    Field {
        name,
        off,
        kind: FieldKind::Text { len },
        useful,
    }
}
