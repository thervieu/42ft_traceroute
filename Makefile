NAME = ft_traceroute

SRCS_DIR = ./srcs/

SRCS =	ft_traceroute.c

OBJS_DIR = objs/

OBJ = $(SRCS:.c=.o)

OBJS = $(addprefix $(OBJS_DIR), $(OBJ))

FLAGS = -Wall -Wextra -Werror

$(OBJS_DIR)%.o : $(SRCS_DIR)%.c
	@mkdir -p $(OBJS_DIR)
	@echo "Compiling" $<
	@gcc $(FLAGS) -c $< -o $@

$(NAME): $(OBJS)
	@gcc $(FLAGS) -o $(NAME) $(OBJS)
	@echo ""
	@echo "Exec ft_traceroute created !"
	@echo "usage: ./ft_traceroute [address]"

all: $(NAME)

clean:
	@echo "Removing objs"
	@rm -rf $(OBJS_DIR)

fclean: clean
	@echo "Removing exec"
	@rm -f $(NAME)

re: fclean all

.PHONY:	all clean fclean re