use crate::{bye::Bye, logkeys::LogKeys};
use clap::Parser;
use color_eyre::eyre::Result;
use crossterm::event::{self};
use ratatui::{DefaultTerminal, Frame, layout::Rect};
use ratatui_textarea::{Input, Key};

#[async_trait::async_trait]
pub trait Screen {
    async fn handle_io(&mut self, input: Input) -> Option<Box<dyn Screen + Send>>;
    fn render(&mut self, f: &mut Frame);
}

#[async_trait::async_trait]
pub trait Section: Send {
    async fn handle_io(&mut self, input: Input) -> Option<Box<dyn Screen>>;
    fn render(&mut self, r: &Rect, f: &mut Frame, focus: bool);
    fn title(&self) -> String;
}

mod helper {
    use std::error::Error;

    use ed25519_dalek_blake2b::{Keypair, PublicKey, SecretKey};
    use ratatui::{
        Frame,
        layout::{Alignment, Constraint, Layout},
        widgets::{Block, Clear, Paragraph, Wrap},
    };

    pub fn validate_field(field: &str) -> bool {
        field.trim().is_empty()
    }

    pub fn keypair_from_str(
        public_key: &str,
        private_key: &str,
    ) -> Result<Keypair, Box<dyn Error>> {
        match (
            PublicKey::from_bytes(&hex::decode(public_key)?),
            SecretKey::from_bytes(&hex::decode(private_key)?),
        ) {
            (Ok(pk), Ok(sk)) => Ok(Keypair {
                secret: sk,
                public: pk,
            }),
            _ => Err("Invalid keypair.".into()),
        }
    }

    pub fn lines_to_string(lines: &[String]) -> String {
        lines
            .iter()
            .fold(String::new(), |acc, l| [acc, l.clone()].concat())
    }

    pub fn render_popup(f: &mut Frame, text: String) {
        let [_, l, _] = Layout::horizontal([
            Constraint::Fill(1),
            Constraint::Percentage(60),
            Constraint::Fill(1),
        ])
        .areas(f.area());
        let [_, l, _] = Layout::vertical([
            Constraint::Fill(1),
            Constraint::Length(6),
            Constraint::Fill(1),
        ])
        .areas(l);
        let popup = Paragraph::new(text)
            .centered()
            .wrap(Wrap { trim: true })
            .alignment(Alignment::Center)
            .block(
                Block::bordered()
                    .title_bottom(" Click enter to close. ")
                    .title_alignment(Alignment::Center),
            );
        f.render_widget(Clear, l);
        f.render_widget(popup, l);
    }
}

mod logkeys {
    use std::sync::{Arc, atomic::AtomicBool};

    use crate::{
        Screen,
        dashboard::Dashboard,
        genkeys::GenKeys,
        helper::{lines_to_string, render_popup, validate_field},
    };
    use blocktion::state::service::{
        Account, AccountExistsRequest, node_rpc_service_client::NodeRpcServiceClient,
    };
    use ratatui::{
        layout::{Alignment, Constraint, Layout},
        style::{Style, Stylize},
        symbols::border,
        widgets::{Block, Borders, Paragraph},
    };
    use ratatui_textarea::{Input, Key, TextArea};
    use tokio::sync::Notify;
    use tonic::Request;

    #[derive(Clone)]
    pub enum Field {
        PublicKey,
        PrivateKey,
        GenerateKey,
    }

    impl Field {
        pub fn toggle_up(&self) -> Option<Self> {
            match self {
                Self::GenerateKey => Some(Self::PrivateKey),
                Self::PrivateKey => Some(Self::PublicKey),
                Self::PublicKey => None,
            }
        }

        pub fn toggle_down(&self) -> Option<Self> {
            match self {
                Self::GenerateKey => None,
                Self::PrivateKey => Some(Self::GenerateKey),
                Self::PublicKey => Some(Self::PrivateKey),
            }
        }
    }

    pub struct LogKeys<'a> {
        pub public_key_textarea: TextArea<'a>,
        pub private_key_textarea: TextArea<'a>,
        pub field: Field,
        pub node: String,
        pub waiting: (Arc<Notify>, AtomicBool),
        pub popup: Option<String>,
    }

    impl LogKeys<'_> {
        pub fn new(node: String) -> Self {
            let mut public_key_textarea = TextArea::default();
            let mut private_key_textarea = TextArea::default();

            public_key_textarea.set_block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Public Key ")
                    .title_alignment(Alignment::Left),
            );
            public_key_textarea.set_cursor_line_style(Style::default());

            private_key_textarea.set_block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Private Key ")
                    .title_alignment(Alignment::Left),
            );
            private_key_textarea.set_cursor_line_style(Style::default());

            public_key_textarea.set_placeholder_text(" Paste your public key here...");
            private_key_textarea.set_placeholder_text(" Paste your private key here...");

            Self {
                node,
                public_key_textarea,
                private_key_textarea,
                field: Field::PublicKey,
                waiting: (Arc::new(Notify::new()), AtomicBool::new(false)),
                popup: None,
            }
        }
    }

    #[async_trait::async_trait]
    impl Screen for LogKeys<'_> {
        async fn handle_io(&mut self, input: Input) -> Option<Box<dyn Screen + Send>> {
            if self.waiting.1.load(std::sync::atomic::Ordering::SeqCst) {
                return None;
            }

            match input {
                Input {
                    key: Key::Enter, ..
                } => {
                    if let Some(_) = self.popup {
                        self.popup = None;
                        return None;
                    }

                    if let Field::GenerateKey = self.field {
                        return Some(Box::new(GenKeys::new(self.node.to_string())));
                    }

                    if validate_field(
                        &self
                            .public_key_textarea
                            .lines()
                            .iter()
                            .fold(String::new(), |acc, l| [acc, l.clone()].concat()),
                    ) {
                        self.public_key_textarea
                            .set_placeholder_text(" A public key is required!");
                        return None;
                    }

                    if validate_field(
                        &self
                            .private_key_textarea
                            .lines()
                            .iter()
                            .fold(String::new(), |acc, l| [acc, l.clone()].concat()),
                    ) {
                        self.private_key_textarea
                            .set_placeholder_text(" A private key is required!");
                        return None;
                    }

                    let public_key = lines_to_string(self.public_key_textarea.lines());

                    match NodeRpcServiceClient::connect(self.node.to_string()).await {
                        Ok(mut conn) => {
                            if let Ok(res) = conn
                                .account_exists(Request::new(AccountExistsRequest {
                                    account: Some(Account {
                                        public_key: public_key.to_string(),
                                    }),
                                }))
                                .await
                            {
                                let res = res.into_inner();
                                if res.exists {
                                    return Some(Box::new(Dashboard::new(&public_key)));
                                }
                            }
                        }

                        _ => {
                            self.popup =
                                Some("Couldn't connect to the node. Try another.".to_string());

                            return None;
                        }
                    };

                    self.popup = Some(
                        "The node does not recognize the account. Try again or generate a new keypair.".to_string(),
                    );

                    None
                }

                Input { key: Key::Up, .. } => {
                    if let Some(f) = self.field.toggle_up() {
                        self.field = f;
                    };
                    None
                }

                Input { key: Key::Down, .. } => {
                    if let Some(f) = self.field.toggle_down() {
                        self.field = f;
                    };
                    None
                }

                key => match self.field {
                    Field::PublicKey => {
                        self.public_key_textarea.input(key);
                        None
                    }
                    Field::PrivateKey => {
                        self.private_key_textarea.input(key);
                        None
                    }
                    _ => None,
                },
            }
        }

        fn render(&mut self, f: &mut ratatui::prelude::Frame) {
            let size = f.area();

            let block = Block::default()
                .title_bottom("Use ↑/↓ to move, enter to continue, ^X to quit")
                .title_alignment(Alignment::Center);
            f.render_widget(block, size);

            let [_, centered] = Layout::default()
                .direction(ratatui::layout::Direction::Vertical)
                .constraints([Constraint::Percentage(5), Constraint::Percentage(90)])
                .areas(size);

            let logkeys_box = Block::bordered()
                .title(" Log your keys to acess your Blocktion account! ".bold())
                .title_alignment(Alignment::Center);
            f.render_widget(logkeys_box, centered);

            let logkeys_chunks = Layout::default()
                .direction(ratatui::layout::Direction::Vertical)
                .constraints([
                    Constraint::Min(3),    // title
                    Constraint::Length(3), // pk
                    Constraint::Min(2),
                    Constraint::Length(3), // sk
                    Constraint::Min(2),
                    Constraint::Length(1), // gen k
                    Constraint::Min(3),
                ])
                .split(centered);

            let input_box_layout = Layout::default()
                .direction(ratatui::layout::Direction::Horizontal)
                .constraints([
                    Constraint::Min(2),
                    Constraint::Percentage(70),
                    Constraint::Min(2),
                ]);

            let input_chunks_pk = input_box_layout.split(logkeys_chunks[1]);
            let input_chunks_sk = input_box_layout.split(logkeys_chunks[3]);

            let mut new_keys_par = Paragraph::new("No keypair yet? Generate one.").centered();

            self.public_key_textarea.set_block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Public Key ")
                    .title_alignment(Alignment::Left),
            );
            self.public_key_textarea
                .set_style(Style::default().fg(ratatui::style::Color::White));
            self.public_key_textarea.set_style(Style::default());
            self.public_key_textarea
                .set_placeholder_style(Style::default().dark_gray());

            self.private_key_textarea.set_block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Secret Key ")
                    .title_alignment(Alignment::Left),
            );
            self.private_key_textarea
                .set_style(Style::default().fg(ratatui::style::Color::White));
            self.private_key_textarea.set_style(Style::default());
            self.private_key_textarea
                .set_placeholder_style(Style::default().dark_gray());

            match self.field {
                Field::PrivateKey => {
                    self.private_key_textarea
                        .set_placeholder_style(Style::default().white());
                    self.private_key_textarea
                        .set_style(Style::default().white());
                    self.private_key_textarea.set_block(
                        Block::default()
                            .borders(Borders::ALL)
                            .border_set(border::DOUBLE)
                            .title(" Secret Key ".bold())
                            .title_alignment(Alignment::Left)
                            .style(Style::default().fg(ratatui::style::Color::LightYellow)),
                    );
                }
                Field::PublicKey => {
                    self.public_key_textarea
                        .set_placeholder_style(Style::default().white());
                    self.public_key_textarea.set_style(Style::default().white());
                    self.public_key_textarea.set_block(
                        Block::default()
                            .borders(Borders::ALL)
                            .border_set(border::DOUBLE)
                            .title(" Public Key ".bold())
                            .title_alignment(Alignment::Left)
                            .style(Style::default().fg(ratatui::style::Color::LightYellow)),
                    );
                }

                Field::GenerateKey => {
                    new_keys_par =
                        Paragraph::new("No keypair yet? Generate one.".bold().light_yellow())
                            .centered();
                }
            };

            f.render_widget(&self.public_key_textarea, input_chunks_pk[1]);
            f.render_widget(&self.private_key_textarea, input_chunks_sk[1]);
            f.render_widget(new_keys_par, input_box_layout.split(logkeys_chunks[5])[1]);

            if let Some(p) = self.popup.clone() {
                render_popup(f, p);
            }
        }
    }
}

mod genkeys {
    use std::error::Error;

    use crate::{
        Screen,
        helper::{keypair_from_str, render_popup},
        logkeys::LogKeys,
    };
    use blocktion::{
        blockchain::transaction::{Data, Transaction},
        state::service::node_rpc_service_client::NodeRpcServiceClient,
    };
    use clipboard::{ClipboardContext, ClipboardProvider};
    use ed25519_dalek_blake2b::Keypair;
    use hex::ToHex;
    use rand::rngs::OsRng;
    use ratatui::{
        layout::{Alignment, Constraint, Layout},
        style::{Style, Stylize},
        symbols::border,
        widgets::{Block, Borders, Paragraph},
    };
    use ratatui_textarea::{Input, Key};
    use tonic::Request;

    const GENERATE_ANOTHER_PAIR: &str = "Not satisfied? Generate another keypair.";

    #[derive(Clone)]
    pub enum Field {
        PublicKey,
        PrivateKey,
        GenerateAnotherKey,
    }

    impl Field {
        pub fn toggle_up(&self) -> Option<Self> {
            match self {
                Self::GenerateAnotherKey => Some(Self::PrivateKey),
                Self::PrivateKey => Some(Self::PublicKey),
                Self::PublicKey => None,
            }
        }

        pub fn toggle_down(&self) -> Option<Self> {
            match self {
                Self::GenerateAnotherKey => None,
                Self::PrivateKey => Some(Self::GenerateAnotherKey),
                Self::PublicKey => Some(Self::PrivateKey),
            }
        }
    }

    #[derive(Clone)]
    pub struct GenKeys {
        pub public_key_content: String,
        pub private_key_content: String,
        pub field: Field,
        pub node: String,
        pub popup: Option<String>,
    }

    impl GenKeys {
        pub fn new(node: String) -> Self {
            let keypair = Keypair::generate(&mut OsRng);

            Self {
                public_key_content: keypair.public.encode_hex(),
                private_key_content: keypair.secret.encode_hex(),
                field: Field::PublicKey,
                node,
                popup: None,
            }
        }
    }

    #[async_trait::async_trait]
    impl Screen for GenKeys {
        async fn handle_io(&mut self, input: Input) -> Option<Box<dyn Screen + Send>> {
            match input {
                Input {
                    key: Key::Enter, ..
                } => {
                    if let Some(_) = self.popup {
                        self.popup = None;
                        return None;
                    }

                    if let Field::GenerateAnotherKey = self.field {
                        return Some(Box::new(GenKeys::new(self.node.to_string())));
                    }

                    let mut logkeys = LogKeys::new(self.node.to_string());

                    logkeys.private_key_textarea.select_all();
                    logkeys.private_key_textarea.cut();
                    logkeys
                        .private_key_textarea
                        .insert_str(&self.private_key_content);

                    logkeys.public_key_textarea.select_all();
                    logkeys.public_key_textarea.cut();
                    logkeys
                        .public_key_textarea
                        .insert_str(&self.public_key_content);

                    match NodeRpcServiceClient::connect(self.node.to_string()).await {
                        Ok(mut conn) => {
                            let keys = match keypair_from_str(
                                &self.public_key_content,
                                &self.private_key_content,
                            ) {
                                Ok(keys) => keys,
                                Err(_) => {
                                    self.popup =
                                        Some("Failed to validate the keys provided.".to_string());
                                    return None;
                                }
                            };
                            let t = match Transaction::sign(
                                Data::CreateUserAccount {
                                    public_key: keys.public.encode_hex(),
                                },
                                &keys.public.encode_hex::<String>(),
                                0,
                                &keys,
                            ) {
                                Ok(t) => t,
                                Err(_) => {
                                    self.popup = Some(
                                        "Failed to sign the create account transaction."
                                            .to_string(),
                                    );
                                    return None;
                                }
                            }
                            .into();
                            if let Ok(res) = conn.transaction(Request::new(t)).await {
                                let res = res.into_inner();

                                if res.status == 0 {
                                    return Some(Box::new(logkeys));
                                }
                            }
                        }

                        _ => {
                            self.popup =
                                Some("Couldn't connect to the node. Try another.".to_string());
                            return None;
                        }
                    };

                    self.popup = Some(
                        "The blockchain did not accept the create account transaction.".to_string(),
                    );
                    None
                }

                Input { key: Key::Up, .. } => {
                    if let Some(f) = self.field.toggle_up() {
                        self.field = f;
                    }
                    None
                }

                Input { key: Key::Down, .. } => {
                    if let Some(f) = self.field.toggle_down() {
                        self.field = f;
                    }
                    None
                }

                Input {
                    key: Key::Char('c'),
                    ctrl: true,
                    ..
                } => {
                    let ctx: Result<ClipboardContext, Box<dyn Error>> = ClipboardProvider::new();

                    if let Ok(mut ctx) = ctx {
                        let contents = match self.field {
                            Field::PublicKey => self.public_key_content.clone(),
                            Field::PrivateKey => self.private_key_content.clone(),
                            _ => return None,
                        };

                        if let Err(_) = ctx.set_contents(contents) { /*todo*/ }
                    }
                    None
                }

                _ => None,
            }
        }

        fn render(&mut self, f: &mut ratatui::prelude::Frame) {
            let size = f.area();

            let block = Block::default()
                .title_bottom(
                    "Use ↑/↓ to move, ^C to copy key to clipboard, enter to continue, ^X to quit",
                )
                .title_alignment(Alignment::Center);
            f.render_widget(block, size);

            let [_, centered] = Layout::default()
                .direction(ratatui::layout::Direction::Vertical)
                .constraints([Constraint::Percentage(5), Constraint::Percentage(90)])
                .areas(size);

            let logkeys_box = Block::bordered()
                .title(" Store the generated keys in a secure place. ".bold())
                .title_alignment(Alignment::Center);
            f.render_widget(logkeys_box, centered);

            let logkeys_chunks = Layout::default()
                .direction(ratatui::layout::Direction::Vertical)
                .constraints([
                    Constraint::Min(3),    // title
                    Constraint::Length(3), // pk
                    Constraint::Min(2),
                    Constraint::Length(3), // sk
                    Constraint::Min(2),
                    Constraint::Length(1), // gen k
                    Constraint::Min(3),
                ])
                .split(centered);

            let input_box_layout = Layout::default()
                .direction(ratatui::layout::Direction::Horizontal)
                .constraints([
                    Constraint::Min(2),
                    Constraint::Percentage(70),
                    Constraint::Min(2),
                ]);
            let mut input_box_pk = Paragraph::new(self.public_key_content.as_str()).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Public Key ")
                    .title_alignment(Alignment::Left),
            );

            let input_chunks_pk = input_box_layout.split(logkeys_chunks[1]);
            let input_chunks_sk = input_box_layout.split(logkeys_chunks[3]);

            let mut input_box_sk = Paragraph::new(self.private_key_content.as_str()).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Secret Key ")
                    .title_alignment(Alignment::Left),
            );

            let mut new_keys_par = Paragraph::new(GENERATE_ANOTHER_PAIR).centered();

            match self.field {
                Field::PrivateKey => {
                    input_box_sk = Paragraph::new(self.private_key_content.as_str())
                        .block(
                            Block::default()
                                .borders(Borders::ALL)
                                .border_set(border::DOUBLE)
                                .title(" Secret Key ".bold())
                                .title_alignment(Alignment::Left)
                                .fg(ratatui::style::Color::LightYellow),
                        )
                        .style(Style::default().fg(ratatui::style::Color::LightYellow));
                }
                Field::PublicKey => {
                    input_box_pk = Paragraph::new(self.public_key_content.as_str())
                        .block(
                            Block::default()
                                .borders(Borders::ALL)
                                .border_set(border::DOUBLE)
                                .title(" Public Key ".bold())
                                .title_alignment(Alignment::Left)
                                .fg(ratatui::style::Color::LightYellow),
                        )
                        .style(Style::default().fg(ratatui::style::Color::LightYellow));
                }

                Field::GenerateAnotherKey => {
                    new_keys_par =
                        Paragraph::new(GENERATE_ANOTHER_PAIR.bold().light_yellow()).centered();
                }
            };

            f.render_widget(input_box_pk, input_chunks_pk[1]);
            f.render_widget(input_box_sk, input_chunks_sk[1]);
            f.render_widget(new_keys_par, input_box_layout.split(logkeys_chunks[5])[1]);

            if let Some(p) = self.popup.clone() {
                render_popup(f, p);
            }
        }
    }
}

mod dashboard {
    use crate::{Screen, Section, dashboard::options::CreateAuction};
    use ratatui::{
        layout::{Alignment, Constraint, Layout},
        style::{Style, Stylize},
        symbols::border,
        text::{Line, Span},
        widgets::{Block, List, ListState, Tabs},
    };
    use ratatui_textarea::{Input, Key};

    #[derive(Clone)]
    pub enum Page {
        Auctions = 0,
        ProfileHistory = 1,
    }

    impl Page {
        fn all() -> Vec<String> {
            vec!["Auctions".to_string(), "Profile History".to_string()]
        }

        fn next(&self) -> Self {
            match self {
                Self::Auctions | Self::ProfileHistory => Self::ProfileHistory,
            }
        }

        fn previous(&self) -> Self {
            match self {
                Self::Auctions | Self::ProfileHistory => Self::Auctions,
            }
        }
    }

    mod options {
        use ratatui::{
            layout::{Alignment, Constraint, Layout},
            style::{Style, Stylize},
            symbols::border,
            widgets::{Block, Borders},
        };
        use ratatui_textarea::{Input, TextArea};

        use crate::{Screen, Section};

        pub enum Field {
            StartAmount,
            Duration,
        }

        pub struct CreateAuction<'a> {
            pub start_amount_textarea: TextArea<'a>,
            pub duration_textarea: TextArea<'a>,
            pub field: Field,
            pub node: String,
        }

        impl<'a> CreateAuction<'a> {
            pub fn new(node: String) -> Self {
                let mut start_amount_textarea = TextArea::default();
                let mut duration_textarea = TextArea::default();

                start_amount_textarea.set_block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" Start Amount ")
                        .title_alignment(Alignment::Left),
                );
                start_amount_textarea.set_cursor_line_style(Style::default());

                duration_textarea.set_block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" Duration ")
                        .title_alignment(Alignment::Left),
                );
                duration_textarea.set_cursor_line_style(Style::default());

                start_amount_textarea.set_placeholder_text(" Insert the amount...");
                duration_textarea.set_placeholder_text(" Insert the duration in secords...");

                Self {
                    node,
                    start_amount_textarea,
                    duration_textarea,
                    field: Field::StartAmount,
                }
            }
        }

        #[async_trait::async_trait]
        impl Section for CreateAuction<'_> {
            fn title(&self) -> String {
                " Create Auction ".to_string()
            }

            async fn handle_io(&mut self, _input: Input) -> Option<Box<dyn Screen>> {
                None
            }

            fn render(
                &mut self,
                r: &ratatui::prelude::Rect,
                f: &mut ratatui::prelude::Frame,
                focus: bool,
            ) {
                self.start_amount_textarea.set_block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" Start Amount ")
                        .title_alignment(Alignment::Left),
                );
                self.start_amount_textarea
                    .set_style(Style::default().fg(ratatui::style::Color::White));
                self.start_amount_textarea.set_style(Style::default());
                self.start_amount_textarea
                    .set_placeholder_style(Style::default().dark_gray());

                self.duration_textarea.set_block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" Secret Key ")
                        .title_alignment(Alignment::Left),
                );
                self.duration_textarea
                    .set_style(Style::default().fg(ratatui::style::Color::White));
                self.duration_textarea.set_style(Style::default());
                self.duration_textarea
                    .set_placeholder_style(Style::default().dark_gray());

                match self.field {
                    Field::StartAmount if focus => {
                        self.start_amount_textarea
                            .set_placeholder_style(Style::default().white());
                        self.start_amount_textarea
                            .set_style(Style::default().white());
                        self.start_amount_textarea.set_block(
                            Block::default()
                                .borders(Borders::ALL)
                                .border_set(border::DOUBLE)
                                .title(" Start Amount ".bold())
                                .title_alignment(Alignment::Left)
                                .style(Style::default().fg(ratatui::style::Color::LightYellow)),
                        );
                    }
                    Field::Duration if focus => {
                        self.duration_textarea
                            .set_placeholder_style(Style::default().white());
                        self.duration_textarea.set_style(Style::default().white());
                        self.duration_textarea.set_block(
                            Block::default()
                                .borders(Borders::ALL)
                                .border_set(border::DOUBLE)
                                .title(" Duration ".bold())
                                .title_alignment(Alignment::Left)
                                .style(Style::default().fg(ratatui::style::Color::LightYellow)),
                        );
                    }
                    _ => {}
                };

                let [_, r, _] = Layout::horizontal([
                    Constraint::Fill(1),
                    Constraint::Percentage(70),
                    Constraint::Fill(1),
                ])
                .areas(*r);

                let [_, lsa, _, ld, _] = Layout::default()
                    .direction(ratatui::layout::Direction::Vertical)
                    .constraints([
                        Constraint::Min(3),
                        Constraint::Length(3),
                        Constraint::Min(2),
                        Constraint::Length(3),
                        Constraint::Min(3),
                    ])
                    .areas(r);

                f.render_widget(&self.start_amount_textarea, lsa);
                f.render_widget(&self.duration_textarea, ld);
            }
        }
    }

    pub enum Area {
        Menu,
        List,
        Body,
    }

    pub struct Dashboard {
        public_key: String,
        page: Page,
        area: Area,
        options_state: ListState,
        option: Box<dyn Section>,
    }

    impl Dashboard {
        pub fn new(public_key: &str) -> Self {
            let mut options_state = ListState::default();
            options_state.select_first();

            let mut menu_state = ListState::default();
            menu_state.select_first();

            Self {
                public_key: public_key.to_string(),
                page: Page::Auctions,
                area: Area::Menu,
                options_state,
                option: Box::new(CreateAuction::new(public_key.to_string())),
            }
        }
    }

    #[async_trait::async_trait]
    impl Screen for Dashboard {
        async fn handle_io(&mut self, input: Input) -> Option<Box<dyn Screen + Send>> {
            match input {
                Input {
                    key: Key::Right, ..
                } => match self.area {
                    Area::Menu => self.page = self.page.next(),
                    Area::List => self.area = Area::Body,
                    Area::Body => {}
                },

                Input { key: Key::Left, .. } => match self.area {
                    Area::Menu => self.page = self.page.previous(),
                    Area::Body => self.area = Area::List,
                    Area::List => {}
                },

                Input { key: Key::Down, .. } => match self.area {
                    Area::Menu => self.area = Area::List,
                    Area::List => self.options_state.select_next(),
                    _ => {}
                },

                Input { key: Key::Up, .. } => match self.area {
                    Area::Menu => {}
                    Area::List => match self.options_state.selected() {
                        Some(0) => self.area = Area::Menu,
                        _ => self.options_state.select_previous(),
                    },
                    Area::Body => self.area = Area::Menu,
                },
                _ => {}
            }
            None
        }

        fn render(&mut self, f: &mut ratatui::prelude::Frame) {
            let size = f.area();

            let block = Block::default()
                .title_bottom("Use ↑/↓/←/→ to move, enter to continue, ^X to quit")
                .title_alignment(Alignment::Center);
            f.render_widget(block, size);

            let chunks = Layout::default()
                .direction(ratatui::layout::Direction::Vertical)
                .constraints([Constraint::Percentage(5), Constraint::Percentage(90)])
                .split(size);

            let [_, centered_menu, _, centered, _] = Layout::vertical([
                Constraint::Min(2),
                Constraint::Min(3),
                Constraint::Length(1),
                Constraint::Percentage(70),
                Constraint::Min(2),
            ])
            .areas(chunks[1]);

            let menu = Tabs::new(
                Page::all()
                    .iter()
                    .map(|p| Line::from(Span::styled(p.clone(), Style::default())))
                    .collect::<Vec<Line>>(),
            )
            .divider("*")
            .block(match self.area {
                Area::Menu => Block::bordered()
                    .title(" Blocktion ".bold().light_yellow())
                    .border_style(Style::default().light_yellow()),
                _ => Block::bordered().title(" Blocktion "),
            })
            .highlight_style(Style::default().bold())
            .select(match self.page.clone().into() {
                Some(i) => i as usize,

                None => 0,
            });
            f.render_widget(menu, centered_menu);

            let [list_layout, _, body_layout] = Layout::horizontal([
                Constraint::Fill(10),
                Constraint::Min(1),
                Constraint::Percentage(80),
            ])
            .areas(centered);

            let list = List::new([" Available", " Create", " Bid"])
                .highlight_style(Style::default().bold())
                .highlight_symbol(" *")
                .scroll_padding(1)
                .block(match self.area {
                    Area::List => Block::bordered()
                        .title(" Options ".bold().light_yellow())
                        .border_style(Style::default().light_yellow()),
                    _ => Block::bordered().title(" Options "),
                });
            f.render_stateful_widget(list, list_layout, &mut self.options_state);

            let page = match self.area {
                Area::Body => Block::bordered()
                    .title(self.option.title().bold())
                    .border_style(Style::default().light_yellow()),
                _ => Block::bordered().title(self.option.title()),
            };
            f.render_widget(page, body_layout);

            self.option
                .render(&body_layout, f, matches!(self.area, Area::Body));
        }
    }
}

mod bye {
    use crate::Screen;
    use ratatui::{
        layout::{Alignment, Constraint, Layout},
        widgets::Paragraph,
    };
    use ratatui_textarea::Input;
    use std::{process::exit, time::Duration};
    use tokio::time::sleep;

    pub const BYE_TIME: Duration = Duration::from_secs(1);

    pub struct Bye;

    #[async_trait::async_trait]
    impl Screen for Bye {
        async fn handle_io(&mut self, _input: Input) -> Option<Box<dyn Screen + Send>> {
            {
                tokio::spawn(async move {
                    sleep(BYE_TIME).await;
                    ratatui::restore();
                    exit(0);
                });
            }

            None
        }

        fn render(&mut self, f: &mut ratatui::prelude::Frame) {
            let [_, l, _] = Layout::vertical([
                Constraint::Fill(1),
                Constraint::Length(1),
                Constraint::Fill(1),
            ])
            .areas(f.area());
            f.render_widget(
                Paragraph::new("See you space cowboy...")
                    .centered()
                    .alignment(Alignment::Center),
                l,
            );
        }
    }
}

struct App {
    current_screen: Box<dyn Screen>,
}

impl App {
    fn new(node: String) -> Self {
        Self {
            current_screen: Box::new(LogKeys::new(node)),
            //current_screen: Box::new(Dashboard::new(&node)),
        }
    }

    async fn run(&mut self, mut terminal: DefaultTerminal) -> Result<()> {
        loop {
            terminal.draw(|frame| self.current_screen.render(frame))?;

            let input = event::read()?.into();

            if let Input {
                key: Key::Char('x'),
                ctrl: true,
                ..
            } = input
            {
                let mut bye = Bye;
                bye.handle_io(Input::default()).await;
                loop {
                    terminal.draw(|frame| bye.render(frame))?;
                }
            }

            if let Some(screen) = self.current_screen.handle_io(input).await {
                self.current_screen = screen;
            }
        }
    }
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long)]
    node: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    color_eyre::install()?;
    let terminal = ratatui::init();
    let mut app = App::new(args.node);
    let result = app.run(terminal).await;
    result
}
