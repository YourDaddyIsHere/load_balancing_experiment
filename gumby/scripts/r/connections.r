library(ggplot2)
library(reshape)

minX <- as.integer(commandArgs(TRUE)[1])
maxX <- as.integer(commandArgs(TRUE)[2])

source(paste(Sys.getenv('R_SCRIPTS_PATH'), 'annotation.r', sep='/'))
df2 <- load_annotations()

i = 1
while(file.exists(paste("total_connections_", toString(i), "_reduced.txt", sep = ''))){
	df <- read.table(paste("total_connections_", toString(i), "_reduced.txt", sep = ''), header = TRUE, check.names = FALSE, na.strings = "?")
	num_columns <- ncol(df) - 1
	df <- mean_max_min(num_columns, df)
	
	p <- ggplot(df) + theme_bw()
	p <- add_annotations(p, df, df2)
	if (num_columns <= 1000){
		p <- p + geom_step(data = df, alpha = 0.8, aes(time, value, group=variable, colour=variable))
	} else {
		p <- p + geom_step(aes(time, mean), colour = '2')
		p <- p + geom_ribbon(alpha = 0.3, aes(time, mean, ymin=min, ymax=max, linetype=NA))
		p <- p + geom_ribbon(alpha = 0.3, aes(time, ymin=Q1, ymax=Q3, linetype=NA))
	}
	p <- p + theme(legend.position = "none")
	p <- p + labs(x = "\nTime into experiment (Seconds)", y = "Connections per peer\n")
	p <- p + xlim(minX, maxX)
	p
	
	ggsave(file=paste("total_connections_", toString(i), ".png", sep = ''), width=8, height=6, dpi=100)
	i = i + 1
}

i = 1
while(file.exists(paste("total_walked_", toString(i), "_reduced.txt", sep = ''))){
	df <- NULL
	for(category in c('walked', 'intro', 'stumbled')){
		subdf <- read.table(paste("total_",category,"_", toString(i), "_reduced.txt", sep = ''), header = TRUE, check.names = FALSE, na.strings = "?")
		subdf <- mean_max_min(1001, subdf)
		subdf$category <- category
		df <- rbind(df, subdf)
	}
	
	p <- ggplot(df) + theme_bw()
	p <- add_annotations(p, df, df2)
	p <- p + facet_grid(category ~ .)
	p <- p + geom_step(aes(time, mean), colour='2')
	p <- p + geom_ribbon(alpha = 0.3, aes(time, mean, ymin=min, ymax=max, linetype=NA))
	p <- p + geom_ribbon(alpha = 0.3, aes(time, ymin=Q1, ymax=Q3))
	p <- p + theme(legend.position = "none")
	p <- p + labs(x = "\nTime into experiment (Seconds)", y = "Connections per peer\n")
	p <- p + xlim(minX, maxX)
	p
	
	ggsave(file=paste("type_connections_", toString(i), ".png", sep = ''), width=8, height=6, dpi=100)
	i = i + 1
}

i = 1
while(file.exists(paste("sum_incomming_connections_", toString(i), "_reduced.txt", sep = ''))){
	df <- read.table(paste("sum_incomming_connections_", toString(i), "_reduced.txt", sep = ''), header = TRUE, check.names = FALSE, na.strings = "?")
	df <- subset(df, df$time == max(df$time))
	df <- melt(df, id="time")
	df <- na.omit(df)
	
	p <- ggplot(df) + theme_bw()
	p <- p + geom_density(aes(x=value))
	p <- p + geom_histogram(aes(x=value, y=..density.., alpha=0.8))
	p <- p + theme(legend.position = "none")
	p <- p + labs(x = "\nSum incomming connections", y = "Density\n")
	p
	
	ggsave(file=paste("incomming_connections_", toString(i), ".png", sep = ''), width=8, height=6, dpi=100)
	i = i + 1
}

