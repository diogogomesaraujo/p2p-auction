use color_eyre::eyre::Result;
use crossterm::event::{self};
use ratatui::{DefaultTerminal, Frame};
use ratatui_textarea::{Input, Key};

use crate::{bye::Bye, logkeys::LogKeys};

#[async_trait::async_trait]
pub trait Screen {
    async fn handle_io(&mut self, input: Input) -> Option<Box<dyn Screen>>;
    fn render(&mut self, f: &mut Frame);
}

mod helper {
    pub fn validate_field(field: &str) -> bool {
        field.trim().is_empty()
    }
}

mod logkeys {
    use crate::{Screen, dashboard::Dashboard, genkeys::GenKeys, helper::validate_field};
    use ratatui::{
        layout::{Alignment, Constraint, Layout},
        style::{Style, Stylize},
        symbols::border,
        widgets::{Block, Borders, Paragraph},
    };
    use ratatui_textarea::{Input, Key, TextArea};

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

    #[derive(Clone)]
    pub struct LogKeys<'a> {
        pub public_key_textarea: TextArea<'a>,
        pub private_key_textarea: TextArea<'a>,
        pub field: Field,
    }

    impl LogKeys<'_> {
        pub fn new() -> Self {
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
                public_key_textarea,
                private_key_textarea,
                field: Field::PublicKey,
            }
        }
    }

    #[async_trait::async_trait]
    impl Screen for LogKeys<'_> {
        async fn handle_io(&mut self, input: Input) -> Option<Box<dyn Screen>> {
            match input {
                Input {
                    key: Key::Enter, ..
                } => {
                    if let Field::GenerateKey = self.field {
                        return Some(Box::new(GenKeys::new()));
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

                    return Some(Box::new(Dashboard::new()));
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

            self.private_key_textarea.set_block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Secret Key ")
                    .title_alignment(Alignment::Left),
            );
            self.private_key_textarea
                .set_style(Style::default().fg(ratatui::style::Color::White));

            match self.field {
                Field::PrivateKey => {
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
        }
    }
}

mod genkeys {
    use std::error::Error;

    use crate::{Screen, logkeys::LogKeys};
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
    }

    impl GenKeys {
        pub fn new() -> Self {
            let keypair = Keypair::generate(&mut OsRng);

            Self {
                public_key_content: keypair.public.encode_hex(),
                private_key_content: keypair.secret.encode_hex(),
                field: Field::PublicKey,
            }
        }
    }

    #[async_trait::async_trait]
    impl Screen for GenKeys {
        async fn handle_io(&mut self, input: Input) -> Option<Box<dyn Screen>> {
            match input {
                Input {
                    key: Key::Enter, ..
                } => {
                    if let Field::GenerateAnotherKey = self.field {
                        return Some(Box::new(GenKeys::new()));
                    }

                    let mut logkeys = LogKeys::new();

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

                    Some(Box::new(logkeys))
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
        }
    }
}

mod dashboard {
    use crate::Screen;
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
        pub struct CreateAuction;
    }

    pub enum Area {
        Menu,
        List,
        Body,
    }

    pub struct Dashboard {
        page: Page,
        area: Area,
        options_state: ListState,
    }

    impl Dashboard {
        pub fn new() -> Self {
            let mut options_state = ListState::default();
            options_state.select_first();

            let mut menu_state = ListState::default();
            menu_state.select_first();

            Self {
                page: Page::Auctions,
                area: Area::Menu,
                options_state,
            }
        }
    }

    #[async_trait::async_trait]
    impl Screen for Dashboard {
        async fn handle_io(&mut self, input: Input) -> Option<Box<dyn Screen>> {
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
                    .border_set(border::DOUBLE)
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
                        .border_set(border::DOUBLE)
                        .border_style(Style::default().light_yellow()),
                    _ => Block::bordered().title(" Options "),
                });
            f.render_stateful_widget(list, list_layout, &mut self.options_state);

            let page = match self.area {
                Area::Body => Block::bordered()
                    .title_alignment(Alignment::Center)
                    .border_set(border::DOUBLE)
                    .border_style(Style::default().light_yellow()),
                _ => Block::bordered(),
            };
            f.render_widget(page, body_layout);
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
        async fn handle_io(&mut self, _input: Input) -> Option<Box<dyn Screen>> {
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
    fn new() -> Self {
        Self {
            current_screen: Box::new(LogKeys::new()),
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

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    let terminal = ratatui::init();
    let mut app = App::new();
    let result = app.run(terminal).await;
    result
}
