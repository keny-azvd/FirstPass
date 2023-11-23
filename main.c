#include <ncurses.h>

int main() {
    initscr(); // Inicializa a biblioteca NCurses
    noecho();  // Não mostrar os caracteres digitados

    int height = 10;
    int width = 40;
    int y = (LINES - height) / 2;
    int x = (COLS - width) / 2;

    // Cria uma nova janela para a caixa de entrada de texto
    WINDOW *input_win = newwin(height, width, y, x);
    box(input_win, 0, 0); // Desenha uma caixa ao redor da janela

    // Habilita o teclado no modo não-bloqueio
    keypad(input_win, TRUE);
    
    // Imprime um prompt na janela
    mvwprintw(input_win, 1, 1, "Digite algo: ");
    wrefresh(input_win);

    char buffer[50];
    wgetstr(input_win, buffer); // Lê a entrada do usuário

    mvwprintw(input_win, 2, 1, "Você digitou: %s", buffer);
    wrefresh(input_win);

    getch(); // Aguarda uma tecla pressionada antes de sair

    // Limpa a janela e finaliza NCurses
    delwin(input_win);
    endwin();

    return 0;
}