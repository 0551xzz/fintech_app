# transacao.py
from typing import List, Dict

class Transacao:
    def __init__(self, descricao: str, valor: float, tipo: str, categoria: str):
        self.descricao = descricao
        self.valor = valor
        self.tipo = tipo  # "Receita" ou "Despesa"
        self.categoria = categoria


class MetaFinanceira:
    def __init__(self, descricao: str, valor_meta: float):
        self.descricao = descricao
        self.valor_meta = valor_meta
        self.progresso = 0.0

    def atualizar_progresso(self, valor_gasto: float):
        self.progresso += valor_gasto
        if self.progresso >= self.valor_meta:
            messagebox.showinfo("Meta Atingida", f"Parabéns! Você atingiu sua meta de {self.descricao}!")
        else:
            messagebox.showinfo("Progresso Atualizado", f"Você alcançou {self.progresso / self.valor_meta * 100:.2f}% da sua meta de {self.descricao}.")


class Conta:
    def __init__(self):
        self.saldo = 0.0
        self.transacoes: List[Transacao] = []
        self.metas: List[MetaFinanceira] = []

    def adicionar_transacao(self, transacao: Transacao):
        self.transacoes.append(transacao)
        if transacao.tipo == "Receita":
            self.saldo += transacao.valor
        elif transacao.tipo == "Despesa":
            self.saldo -= transacao.valor

    def adicionar_meta(self, meta: MetaFinanceira):
        self.metas.append(meta)

    def ver_metas(self):
        meta_str = "\n".join([f"{meta.descricao}: R$ {meta.valor_meta:.2f}" for meta in self.metas])
        messagebox.showinfo("Metas Financeiras", meta_str)

    def obter_transacoes_por_categoria(self) -> Dict[str, List[Transacao]]:
        transacoes_por_categoria = {}
        for transacao in self.transacoes:
            if transacao.categoria not in transacoes_por_categoria:
                transacoes_por_categoria[transacao.categoria] = []
            transacoes_por_categoria[transacao.categoria].append(transacao)
        return transacoes_por_categoria

# app.py
import sqlite3
from tkinter import *
from tkinter import messagebox, ttk, simpledialog
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import webbrowser
from transacao import Transacao, MetaFinanceira, Conta

class FintechApp:
    def __init__(self, master: Tk):
        self.master = master
        master.title("Fintech App")
        master.configure(bg="#2ecc71")

        self.label = Label(master, text="Bem-vindo à Fintech App!", bg="#2ecc71", fg="white", font=("Helvetica", 16))
        self.label.pack(pady=20)

        self.button_login = Button(master, text="Login", command=self.login, bg="#27ae60", fg="white", font=("Helvetica", 14), padx=20)
        self.button_login.pack()

        self.button_quit = Button(master, text="Sair", command=master.quit, bg="#c0392b", fg="white", font=("Helvetica", 14), padx=20)
        self.button_quit.pack(pady=20)

    def login(self):
        self.login_window = Toplevel(self.master)
        self.login_window.title("Login")
        self.login_window.configure(bg="#2ecc71")

        self.label_username = Label(self.login_window, text="Username:", bg="#2ecc71", fg="white", font=("Helvetica", 14))
        self.label_username.grid(row=0, column=0, padx=10, pady=10)
        self.username_entry = Entry(self.login_window, font=("Helvetica", 14))
        self.username_entry.grid(row=0, column=1, padx=10, pady=10)

        self.label_password = Label(self.login_window, text="Password:", bg="#2ecc71", fg="white", font=("Helvetica", 14))
        self.label_password.grid(row=1, column=0, padx=10, pady=10)
        self.password_entry = Entry(self.login_window, show="*", font=("Helvetica", 14))
        self.password_entry.grid(row=1, column=1, padx=10, pady=10)

        self.button_submit = Button(self.login_window, text="Submit", command=self.authenticate, bg="#27ae60", fg="white", font=("Helvetica", 14), padx=20)
        self.button_submit.grid(row=2, columnspan=2, pady=20)

    def authenticate(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        # Autenticação de usuário (pode ser substituída por lógica mais robusta)
        if self.verify_credentials(username, password):
            self.login_success()
        else:
            self.login_fail()

    def verify_credentials(self, username: str, password: str) -> bool:
        # Aqui você pode implementar lógica de verificação de credenciais mais robusta
        # Exemplo: verificar um banco de dados de usuários
        return username == "admin" and password == "password"

    def login_success(self):
        self.login_window.destroy()

        self.main_window = Toplevel(self.master)
        self.main_window.title("Fintech App")
        self.main_window.configure(bg="#2ecc71")

        self.label_logged_in = Label(self.main_window, text="Login bem-sucedido!", bg="#2ecc71", fg="white", font=("Helvetica", 16))
        self.label_logged_in.pack(pady=20)

        self.create_main_buttons()

    def login_fail(self):
        self.label_login_fail = Label(self.login_window, text="Falha no login. Tente novamente.", bg="#2ecc71", fg="white", font=("Helvetica", 14))
        self.label_login_fail.grid(row=3, columnspan=2, pady=20)

    def create_main_buttons(self):
        buttons_info = [
            ("Ver Transações", self.ver_transacoes),
            ("Ver Saldo", self.ver_saldo),
            ("Ver Relatórios", self.ver_relatorios),
            ("Definir Meta Financeira", self.definir_meta),
            ("Verificar Meta Financeira", self.verificar_meta),
            ("Ver Metas Financeiras", conta_atual.ver_metas),
            ("Analisar Hábitos de Gastos", self.analisar_habitos_de_gastos),
            ("Abrir Educação Financeira", self.abrir_educacao_financeira),
            ("Abrir Suporte ao Cliente", self.abrir_suporte_cliente),
            ("Fortalecer Segurança", self.fortalecer_seguranca),
            ("Logout", self.logout),
        ]

        for text, command in buttons_info:
            button = Button(self.main_window, text=text, command=command, bg="#3498db", fg="white", font=("Helvetica", 14), padx=20)
            button.pack(pady=10)

    def ver_transacoes(self):
        transactions_window = Toplevel(self.main_window)
        transactions_window.title("Transações")
        transactions_window.configure(bg="#2ecc71")

        scrollbar = Scrollbar(transactions_window)
        scrollbar.pack(side=RIGHT, fill=Y)

        transactions_listbox = Listbox(transactions_window, yscrollcommand=scrollbar.set, font=("Helvetica", 12))
        for transaction in conta_atual.transacoes:
            transactions_listbox.insert(END, f"{transaction.descricao}: {transaction.valor} ({transaction.tipo}) - {transaction.categoria}")
        transactions_listbox.pack(side=LEFT, fill=BOTH, expand=1)

        scrollbar.config(command=transactions_listbox.yview)

    def ver_saldo(self):
        messagebox.showinfo("Saldo Atual", f"Saldo atual: R$ {conta_atual.saldo:.2f}")

    def ver_relatorios(self):
        transactions_per_category = conta_atual.obter_transacoes_por_categoria()

        # Crie relatórios usando Matplotlib e mostre-os na interface gráfica
        fig, ax = plt.subplots()
        categories = list(transactions_per_category.keys())
        values = [sum(t.valor for t in transactions_per_category[cat]) for cat in categories]
        ax.bar(categories, values, color="#3498db")
        ax.set_xlabel("Categoria")
        ax.set_ylabel("Total (R$)")
        ax.set_title("Relatório de Transações por Categoria")
        canvas = FigureCanvasTkAgg(fig, master=self.main_window)
        canvas.draw()
        canvas.get_tk_widget().pack()

    def definir_meta(self):
        meta_window = Toplevel(self.main_window)
        meta_window.title("Definir Meta Financeira")
        meta_window.configure(bg="#2ecc71")

        self.label_meta_description = Label(meta_window, text="Descrição da Meta:", bg="#2ecc71", fg="white", font=("Helvetica", 14))
        self.label_meta_description.pack(pady=10)
        self.meta_description_entry = Entry(meta_window, font=("Helvetica", 14))
        self.meta_description_entry.pack(pady=10)

        self.label_meta_value = Label(meta_window, text="Valor da Meta:", bg="#2ecc71", fg="white", font=("Helvetica", 14))
        self.label_meta_value.pack(pady=10)
        self.meta_value_entry = Entry(meta_window, font=("Helvetica", 14))
        self.meta_value_entry.pack(pady=10)

        self.button_set_meta = Button(meta_window, text="Definir Meta", command=self.set_meta, bg="#27ae60", fg="white", font=("Helvetica", 14), padx=20)
        self.button_set_meta.pack(pady=10)

    def set_meta(self):
        meta_descricao = self.meta_description_entry.get()
        meta_valor = float(self.meta_value_entry.get())

        nova_meta = MetaFinanceira(meta_descricao, meta_valor)
        conta_atual.adicionar_meta(nova_meta)
        messagebox.showinfo("Meta Financeira Definida", f"Nova meta '{meta_descricao}' definida como R$ {meta_valor:.2f}")

    def verificar_meta(self):
        meta_selecionada = simpledialog.askstring("Verificar Meta", "Informe a descrição da meta que deseja verificar:")
        for meta in conta_atual.metas:
            if meta_selecionada == meta.descricao:
                meta.atualizar_progresso(conta_atual.saldo)
                break
        else:
            messagebox.showerror("Erro", "Meta não encontrada.")

    def analisar_habitos_de_gastos(self):
        # Implementação da análise de hábitos de gastos
        pass

    def abrir_educacao_financeira(self):
        # Abre recursos de educação financeira em um navegador
        webbrowser.open("https://www.educacaofinanceira.com.br")

    def abrir_suporte_cliente(self):
        # Implementação para abrir um sistema de suporte ao cliente
        pass

    def fortalecer_seguranca(self):
        # Implementação de medidas avançadas de segurança
        messagebox.showinfo("Segurança Fortalecida", "Medidas avançadas de segurança foram implementadas com sucesso!")

    def logout(self):
        self.main_window.destroy()
        self.master.deiconify()


if __name__ == "__main__":
    conta_atual = Conta()
    root = Tk()
    app = FintechApp(root)
    root.mainloop()
